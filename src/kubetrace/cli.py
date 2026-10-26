"""Command-line interface for fixture and Kubernetes diagnostics."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from kubetrace.engine import (
    EvidenceCollector,
    EvidenceValidationError,
    FixtureCollector,
    run_diagnostic,
)
from kubetrace.kubernetes_collector import KubernetesCollector
from kubetrace.models import EVIDENCE_SCHEMA_VERSION, DiagnosticReport
from kubetrace.reporting import report_payload, to_json, validation_error_payload


@dataclass(frozen=True)
class _KubernetesSession:
    collector: EvidenceCollector
    close: Callable[[], None]


class _KubernetesSetupError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class _UnavailableKubernetesCollector:
    namespace: str
    service_name: str
    code: str
    message: str

    def collect(self) -> Mapping[str, Any]:
        collected_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        return {
            "schemaVersion": EVIDENCE_SCHEMA_VERSION,
            "collection": {
                "source": "kubernetes-api",
                "collectedAt": collected_at,
                "status": "incomplete",
                "scope": {
                    "namespace": self.namespace,
                    "serviceName": self.service_name,
                },
                "issues": [
                    {
                        "operation": "configure_client",
                        "code": self.code,
                        "message": self.message,
                        "status": None,
                    }
                ],
            },
        }


def _terminal_safe(value: str) -> str:
    """Escape control and non-ASCII characters before terminal display."""

    return value.encode("unicode_escape").decode("ascii")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kubetrace",
        description="Evaluate deterministic Kubernetes network diagnostics.",
    )
    modes = parser.add_subparsers(dest="mode", required=True)

    fixture = modes.add_parser("fixture", help="read evidence from a JSON fixture")
    fixture.add_argument("path", help="path to a KubeTrace fixture JSON file")

    kubernetes = modes.add_parser(
        "kubernetes",
        help="collect read-only evidence from a Kubernetes API server",
    )
    kubernetes.add_argument(
        "-n",
        "--namespace",
        required=True,
        help="namespace containing the target Service",
    )
    kubernetes.add_argument(
        "-s",
        "--service",
        required=True,
        help="name of the target Service",
    )
    kubernetes.add_argument(
        "--context",
        help="kubeconfig context (the current context is used when omitted)",
    )
    kubernetes.add_argument(
        "--kubeconfig",
        help="kubeconfig path (the Kubernetes client default is used when omitted)",
    )
    kubernetes.add_argument(
        "--direction", choices=("ingress", "egress"), help="traffic direction"
    )
    kubernetes.add_argument("--protocol", choices=("TCP", "UDP", "SCTP"), default="TCP")
    kubernetes.add_argument("--port", type=int, help="numeric traffic port")
    kubernetes.add_argument("--peer-namespace", help="peer namespace name")
    kubernetes.add_argument("--peer-ip", help="peer IP address")
    kubernetes.add_argument(
        "--peer-namespace-label", action="append", default=[], metavar="KEY=VALUE"
    )
    kubernetes.add_argument(
        "--peer-pod-label", action="append", default=[], metavar="KEY=VALUE"
    )
    return parser


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] not in {"fixture", "kubernetes", "-h", "--help"}:
        values.insert(0, "fixture")
    return _parser().parse_args(values)


def _close_quietly(close: Callable[[], None]) -> None:
    try:
        close()
    except Exception:
        # Cleanup failure must not expose client or transport details.
        pass


def _create_kubernetes_session(
    namespace: str,
    service_name: str,
    kubeconfig: str | None,
    context: str | None,
    traffic: Mapping[str, Any] | None = None,
) -> _KubernetesSession:
    try:
        from kubernetes import client, config
    except ImportError as error:
        raise _KubernetesSetupError(
            "dependency_unavailable",
            "Kubernetes mode requires the optional Kubernetes client dependency.",
        ) from error

    api_client: Any | None = None
    try:
        config_arguments: dict[str, Any] = {"persist_config": False}
        if kubeconfig is not None:
            config_arguments["config_file"] = kubeconfig
        if context is not None:
            config_arguments["context"] = context
        config.load_kube_config(**config_arguments)

        api_client = client.ApiClient()
        collector = KubernetesCollector(
            core_api=client.CoreV1Api(api_client),
            discovery_api=client.DiscoveryV1Api(api_client),
            networking_api=client.NetworkingV1Api(api_client),
            namespace=namespace,
            service_name=service_name,
            clock=lambda: datetime.now(UTC),
            traffic=traffic,
        )
    except Exception as error:
        if api_client is not None:
            close = getattr(api_client, "close", None)
            if callable(close):
                _close_quietly(close)
        raise _KubernetesSetupError(
            "configuration_error",
            "Kubernetes client configuration failed.",
        ) from error

    close = getattr(api_client, "close", None)
    return _KubernetesSession(
        collector=collector,
        close=close if callable(close) else lambda: None,
    )


def _parse_cli_labels(values: Sequence[str], option: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key or not key.isprintable() or not item.isprintable():
            raise EvidenceValidationError([f"{option} must use printable KEY=VALUE"])
        if key in labels and labels[key] != item:
            raise EvidenceValidationError([f"{option} repeats {key} inconsistently"])
        labels[key] = item
    return labels


def _traffic_from_arguments(arguments: argparse.Namespace) -> Mapping[str, Any] | None:
    namespace_labels = _parse_cli_labels(
        arguments.peer_namespace_label, "--peer-namespace-label"
    )
    pod_labels = _parse_cli_labels(arguments.peer_pod_label, "--peer-pod-label")
    requested = any(
        (
            arguments.direction,
            arguments.port,
            arguments.peer_namespace,
            arguments.peer_ip,
            namespace_labels,
            pod_labels,
        )
    )
    if not requested:
        return None
    if arguments.direction is None or arguments.port is None:
        raise EvidenceValidationError(
            ["traffic evaluation requires both --direction and --port"]
        )
    if not 1 <= arguments.port <= 65535:
        raise EvidenceValidationError(["--port must be between 1 and 65535"])
    peer: dict[str, Any] = {}
    if arguments.peer_namespace is not None:
        peer["namespace"] = arguments.peer_namespace
    if arguments.peer_ip is not None:
        try:
            peer["ip"] = str(ip_address(arguments.peer_ip))
        except ValueError as error:
            raise EvidenceValidationError(
                ["--peer-ip must be a valid IP address"]
            ) from error
    if namespace_labels:
        peer["namespaceLabels"] = namespace_labels
    if pod_labels:
        peer["podLabels"] = pod_labels
    return {
        "direction": arguments.direction,
        "protocol": arguments.protocol,
        "port": arguments.port,
        "peer": peer,
    }


def _run_kubernetes(
    arguments: argparse.Namespace,
    session_factory: Callable[
        [str, str, str | None, str | None, Mapping[str, Any] | None],
        _KubernetesSession,
    ],
) -> DiagnosticReport:
    traffic = _traffic_from_arguments(arguments)
    try:
        session = session_factory(
            arguments.namespace,
            arguments.service,
            arguments.kubeconfig,
            arguments.context,
            traffic,
        )
    except _KubernetesSetupError as error:
        return run_diagnostic(
            _UnavailableKubernetesCollector(
                namespace=arguments.namespace,
                service_name=arguments.service,
                code=error.code,
                message=error.message,
            )
        )

    try:
        return run_diagnostic(session.collector)
    finally:
        _close_quietly(session.close)


def main(
    argv: Sequence[str] | None = None,
    *,
    kubernetes_session_factory: Callable[
        [str, str, str | None, str | None, Mapping[str, Any] | None],
        _KubernetesSession,
    ] = _create_kubernetes_session,
) -> int:
    """Run one investigation and write its versioned report."""

    arguments = _parse_arguments(argv)
    try:
        if arguments.mode == "fixture":
            report = run_diagnostic(FixtureCollector(arguments.path))
        else:
            report = _run_kubernetes(arguments, kubernetes_session_factory)
    except EvidenceValidationError as error:
        print(to_json(validation_error_payload(error.errors)), end="")
        print(_terminal_safe(f"VALIDATION_ERROR: {error}"), file=sys.stderr)
        return 2

    print(to_json(report_payload(report)), end="")
    print(_terminal_safe(report.summary), file=sys.stderr)
    return 0
