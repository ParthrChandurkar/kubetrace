from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from kubetrace.cli import _KubernetesSession, main
from kubetrace.engine import EvidenceValidationError, normalize, run_diagnostic
from kubetrace.hubble_collector import (
    HubbleCollector,
    HubbleRequest,
    SubprocessHubbleClient,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"
NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


class StaticCollector:
    def __init__(self, value: dict[str, Any]) -> None:
        self.value = value

    def collect(self) -> dict[str, Any]:
        return self.value


class FakeHubble:
    def __init__(self, result: str | bytes | Exception) -> None:
        self.result = result
        self.requests: list[HubbleRequest] = []

    def observe(self, request: HubbleRequest) -> str | bytes:
        self.requests.append(request)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def base_evidence() -> dict[str, Any]:
    return json.loads(
        (FIXTURES / "service-matching-pods-not-ready.json").read_text(encoding="utf-8")
    )


def response(*, verdict: str = "DROPPED", policy: str | None = "L3_L4") -> str:
    value = {
        "flow": {
            "time": "2026-10-26T11:59:45Z",
            "verdict": verdict,
            "traffic_direction": "INGRESS",
            "source": {"namespace": "client", "pod_name": "caller", "identity": 2},
            "destination": {
                "namespace": "shop",
                "pod_name": "checkout-abc12",
                "identity": 3,
            },
            "IP": {"source": "192.0.2.10", "destination": "10.244.0.10"},
            "l4": {"TCP": {"source_port": 40000, "destination_port": 443}},
        }
    }
    if policy is not None:
        value["flow"]["policy_match_type"] = policy
        value["flow"]["drop_reason_desc"] = "POLICY_DENIED"
    return json.dumps(value)


def collect(result: str | bytes | Exception, **budgets: Any) -> dict[str, Any]:
    client = FakeHubble(result)
    collector = HubbleCollector(
        StaticCollector(base_evidence()), client, lambda: NOW, **budgets
    )
    evidence = dict(collector.collect())
    assert client.requests[0].start.isoformat() == "2026-10-26T11:59:00+00:00"
    assert client.requests[0].end == NOW
    return evidence


def test_success_projects_only_bounded_metadata() -> None:
    raw = collect(response())

    assert raw["collection"]["hubbleFlowCollection"]["status"] == "complete"
    assert raw["flows"] == [
        {
            "timestamp": "2026-10-26T11:59:45Z",
            "verdict": "DROPPED",
            "direction": "ingress",
            "source": {
                "namespace": "client",
                "pod": "caller",
                "identity": 2,
                "ip": "192.0.2.10",
            },
            "destination": {
                "namespace": "shop",
                "pod": "checkout-abc12",
                "identity": 3,
                "ip": "10.244.0.10",
            },
            "protocol": "TCP",
            "sourcePort": 40000,
            "destinationPort": 443,
            "dropReason": "POLICY_DENIED",
            "policyRelated": True,
        }
    ]
    assert "annotations" not in json.dumps(raw["flows"])


def test_explicit_policy_drop_is_confirmed_but_generic_drop_is_not() -> None:
    explicit = run_diagnostic(StaticCollector(collect(response())))
    generic = run_diagnostic(StaticCollector(collect(response(policy=None))))

    assert any("policy-related" in item for item in explicit.confirmed_causes)
    assert not any("policy-related" in item for item in generic.confirmed_causes)
    assert any("not attributed" in item for item in generic.limitations)


def test_forwarded_flow_does_not_claim_application_success() -> None:
    report = run_diagnostic(
        StaticCollector(collect(response(verdict="FORWARDED", policy=None)))
    )

    assert any("forwarded" in item.lower() for item in report.derived_findings)
    assert any("application-level success" in item for item in report.limitations)


def test_policy_drop_missing_direction_is_possible_not_confirmed() -> None:
    raw = collect(response())
    raw["flows"][0]["direction"] = None
    report = run_diagnostic(StaticCollector(raw))

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any("requires complete source" in item for item in report.limitations)


def test_empty_complete_window_is_negative_observation_not_proof() -> None:
    report = run_diagnostic(StaticCollector(collect("")))

    assert any("No matching" in item for item in report.derived_findings)
    assert any("does not prove" in item for item in report.limitations)


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (subprocess.TimeoutExpired("hubble", 1), "timeout"),
        (OSError("secret transport detail"), "transport_error"),
        (RuntimeError("credential=secret"), "transport_error"),
    ],
)
def test_failures_are_incomplete_and_sanitized(failure: Exception, code: str) -> None:
    raw = collect(failure)
    rendered = json.dumps(raw)

    assert raw["collection"]["hubbleFlowCollection"]["status"] == "incomplete"
    assert raw["collection"]["hubbleFlowCollection"]["issues"][0]["code"] == code
    assert "secret" not in rendered
    confirmed = run_diagnostic(StaticCollector(raw)).confirmed_causes
    assert len(confirmed) == 1
    assert "Ready=False" in confirmed[0]


def test_truncation_is_incomplete_and_cannot_confirm_policy_drop() -> None:
    raw = collect("\n".join((response(), response())), max_flows=1)
    report = run_diagnostic(StaticCollector(raw))

    assert raw["collection"]["hubbleFlowCollection"]["truncated"] is True
    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any("truncated" in item for item in report.limitations)


def test_duplicate_records_are_deduplicated_deterministically() -> None:
    raw = collect("\n".join((response(), response())))
    evidence = normalize(raw)

    assert len(evidence.flow_evidence.flows) == 1  # type: ignore[union-attr]


def test_contradictory_verdicts_cannot_confirm_policy_drop() -> None:
    raw = collect("\n".join((response(), response(verdict="FORWARDED", policy=None))))
    report = run_diagnostic(StaticCollector(raw))

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any("contradictory verdicts" in item for item in report.limitations)


def test_malformed_response_and_oversize_output_are_incomplete() -> None:
    malformed = collect("not-json")
    oversized = collect(b"x" * 101, max_output_bytes=100)

    assert malformed["collection"]["hubbleFlowCollection"]["status"] == "incomplete"
    assert oversized["collection"]["hubbleFlowCollection"]["status"] == "incomplete"


def test_invalid_fixture_flow_fields_are_rejected() -> None:
    raw = collect(response())
    raw["flows"][0]["source"]["ip"] = "not-an-ip"

    with pytest.raises(EvidenceValidationError):
        normalize(raw)


def test_external_name_skips_hubble() -> None:
    raw = base_evidence()
    raw["service"]["spec"] = {
        "type": "ExternalName",
        "externalName": "example.invalid",
    }
    client = FakeHubble(response())

    result = HubbleCollector(StaticCollector(raw), client, lambda: NOW).collect()

    assert client.requests == []
    assert "hubbleFlowCollection" not in result["collection"]


def test_collection_does_not_mutate_wrapped_evidence() -> None:
    raw = base_evidence()
    original = deepcopy(raw)

    HubbleCollector(StaticCollector(raw), FakeHubble(""), lambda: NOW).collect()

    assert raw == original


def test_subprocess_client_uses_bounded_argument_array(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(command: list[str], **options: Any) -> SimpleNamespace:
        captured.update(command=command, options=options)
        return SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    request = HubbleRequest(NOW, NOW, 10, 3.0, 100)

    assert SubprocessHubbleClient("hubble-bin", "relay:4245").observe(request) == b""
    assert captured["command"] == [
        "hubble-bin",
        "--server",
        "relay:4245",
        "observe",
        "--output",
        "json",
        "--since",
        "2026-10-26T12:00:00Z",
        "--until",
        "2026-10-26T12:00:00Z",
        "--last",
        "11",
    ]
    assert captured["options"]["shell"] is False
    assert captured["options"]["timeout"] == 3.0


def test_cli_enables_hubble_only_when_requested(
    capsys: pytest.CaptureFixture[str],
) -> None:
    clients: list[FakeHubble] = []

    def session_factory(*_args: Any) -> _KubernetesSession:
        return _KubernetesSession(StaticCollector(base_evidence()), lambda: None)

    def client_factory(executable: str, server: str | None) -> FakeHubble:
        assert executable == "custom-hubble"
        assert server == "unix:///relay.sock"
        client = FakeHubble(response())
        clients.append(client)
        return client

    status = main(
        [
            "kubernetes",
            "--namespace",
            "shop",
            "--service",
            "checkout",
            "--hubble",
            "--hubble-executable",
            "custom-hubble",
            "--hubble-server",
            "unix:///relay.sock",
        ],
        kubernetes_session_factory=session_factory,
        hubble_client_factory=client_factory,
    )

    assert status == 0
    assert clients and clients[0].requests
    assert "Hubble observed" in capsys.readouterr().out


def test_fixture_cli_never_constructs_hubble_client(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def unexpected(*_args: Any) -> FakeHubble:
        raise AssertionError("fixture mode must not initialize Hubble")

    status = main(
        [str(FIXTURES / "service-no-ready-endpoints.json")],
        hubble_client_factory=unexpected,
    )

    assert status == 0
    capsys.readouterr()
