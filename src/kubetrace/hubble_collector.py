"""Bounded, optional Hubble flow evidence collection."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from kubetrace.engine import EvidenceCollector


@dataclass(frozen=True)
class HubbleRequest:
    start: datetime
    end: datetime
    max_flows: int
    timeout_seconds: float
    max_output_bytes: int


class HubbleClient(Protocol):
    def observe(self, request: HubbleRequest) -> str | bytes: ...


class SubprocessHubbleClient:
    """Invoke the Hubble CLI without a shell or cluster-controlled arguments."""

    def __init__(self, executable: str = "hubble", server: str | None = None) -> None:
        self._executable = executable
        self._server = server

    def observe(self, request: HubbleRequest) -> bytes:
        command = [self._executable]
        if self._server:
            command.extend(("--server", self._server))
        command.extend(
            (
                "observe",
                "--output",
                "json",
                "--since",
                _render_time(request.start),
                "--until",
                _render_time(request.end),
                "--last",
                str(request.max_flows + 1),
            )
        )
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            timeout=request.timeout_seconds,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("hubble command failed")
        if len(result.stdout) > request.max_output_bytes:
            raise ValueError("hubble output limit exceeded")
        return result.stdout


class HubbleCollector:
    """Decorate Kubernetes evidence with a sanitized Hubble flow window."""

    def __init__(
        self,
        base_collector: EvidenceCollector,
        client: HubbleClient,
        clock: Callable[[], datetime],
        *,
        window_seconds: int = 60,
        max_flows: int = 100,
        timeout_seconds: float = 10.0,
        max_output_bytes: int = 1_048_576,
    ) -> None:
        if not 1 <= window_seconds <= 3600:
            raise ValueError("window_seconds must be between 1 and 3600")
        if not 1 <= max_flows <= 1000:
            raise ValueError("max_flows must be between 1 and 1000")
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise ValueError("Hubble budgets must be positive")
        self._base = base_collector
        self._client = client
        self._clock = clock
        self._window_seconds = window_seconds
        self._max_flows = max_flows
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    def collect(self) -> Mapping[str, Any]:
        evidence = deepcopy(dict(self._base.collect()))
        service = evidence.get("service")
        if isinstance(service, Mapping) and isinstance(service.get("spec"), Mapping):
            if service["spec"].get("type") == "ExternalName":
                return evidence
        end = self._clock().astimezone(UTC)
        start = end - timedelta(seconds=self._window_seconds)
        collection = evidence.setdefault("collection", {})
        flow_collection: dict[str, Any] = {
            "status": "incomplete",
            "window": {"start": _render_time(start), "end": _render_time(end)},
            "truncated": False,
            "issues": [],
        }
        collection["hubbleFlowCollection"] = flow_collection
        evidence["flows"] = []
        request = HubbleRequest(
            start, end, self._max_flows, self._timeout_seconds, self._max_output_bytes
        )
        try:
            payload = self._client.observe(request)
            if isinstance(payload, bytes):
                if len(payload) > self._max_output_bytes:
                    raise ValueError
                text = payload.decode("utf-8")
            elif isinstance(payload, str):
                if len(payload.encode("utf-8")) > self._max_output_bytes:
                    raise ValueError
                text = payload
            else:
                raise TypeError
            projected = [_project_response(line) for line in _json_records(text)]
            if len(projected) > self._max_flows:
                flow_collection["truncated"] = True
                projected = projected[: self._max_flows]
            evidence["flows"] = projected
            flow_collection["status"] = (
                "incomplete" if flow_collection["truncated"] else "complete"
            )
        except (subprocess.TimeoutExpired, TimeoutError):
            _issue(flow_collection, "timeout", "Hubble observation timed out.")
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError):
            _issue(
                flow_collection, "malformed_response", "Hubble returned invalid data."
            )
        except (OSError, RuntimeError):
            _issue(flow_collection, "transport_error", "Hubble observation failed.")
        except Exception:
            _issue(flow_collection, "client_error", "Hubble observation failed.")
        return evidence


def _issue(collection: dict[str, Any], code: str, message: str) -> None:
    collection["issues"].append(
        {"operation": "observe_flows", "code": code, "message": message, "status": None}
    )


def _render_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _json_records(text: str) -> Sequence[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, Mapping):
            raise TypeError
        records.append(value)
    return records


def _project_response(response: Mapping[str, Any]) -> dict[str, Any]:
    flow = response.get("flow", response)
    if not isinstance(flow, Mapping):
        raise TypeError
    source = _endpoint(flow.get("source"), flow, "source")
    destination = _endpoint(flow.get("destination"), flow, "destination")
    protocol, source_port, destination_port = _layer4(flow.get("l4"))
    verdict = flow.get("verdict")
    timestamp = flow.get("time", flow.get("timestamp"))
    if not isinstance(verdict, str) or not isinstance(timestamp, str):
        raise TypeError
    drop_reason = flow.get("drop_reason_desc", flow.get("dropReason"))
    if drop_reason is not None and not isinstance(drop_reason, str):
        raise TypeError
    denied_by = (
        *_policy_list(flow.get("ingress_denied_by")),
        *_policy_list(flow.get("egress_denied_by")),
    )
    policy_related = drop_reason in {"POLICY_DENIED", "POLICY_DENY"} or bool(denied_by)
    direction = flow.get("traffic_direction", flow.get("direction"))
    if isinstance(direction, str):
        direction = direction.lower()
    else:
        direction = None
    return {
        "timestamp": timestamp,
        "verdict": verdict.upper(),
        "direction": direction,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "sourcePort": source_port,
        "destinationPort": destination_port,
        "dropReason": drop_reason,
        "policyRelated": policy_related,
    }


def _endpoint(value: Any, flow: Mapping[str, Any], side: str) -> dict[str, Any]:
    item = value if isinstance(value, Mapping) else {}
    ip_layer = flow.get("IP")
    if not isinstance(ip_layer, Mapping):
        ip_layer = flow.get("ip") if isinstance(flow.get("ip"), Mapping) else {}
    return {
        "namespace": item.get("namespace"),
        "pod": item.get("pod_name", item.get("pod")),
        "identity": item.get("identity"),
        "ip": ip_layer.get(side),
    }


def _layer4(value: Any) -> tuple[str | None, int | None, int | None]:
    if not isinstance(value, Mapping):
        return None, None, None
    for key in ("TCP", "UDP", "SCTP", "tcp", "udp", "sctp"):
        ports = value.get(key)
        if isinstance(ports, Mapping):
            return (
                key.upper(),
                ports.get("source_port", ports.get("sourcePort")),
                ports.get("destination_port", ports.get("destinationPort")),
            )
    return None, None, None


def _policy_list(value: Any) -> tuple[Mapping[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(
        isinstance(item, Mapping) for item in value
    ):
        raise TypeError
    return tuple(value)
