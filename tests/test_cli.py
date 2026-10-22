from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from kubetrace.cli import (
    _create_kubernetes_session,
    _KubernetesSession,
    _KubernetesSetupError,
    main,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"


class StaticCollector:
    def __init__(self, evidence: dict[str, Any]) -> None:
        self.evidence = evidence

    def collect(self) -> dict[str, Any]:
        return self.evidence


def load_fixture(filename: str = "service-no-ready-endpoints.json") -> dict[str, Any]:
    return json.loads((FIXTURES / filename).read_text(encoding="utf-8"))


def write_fixture(tmp_path: Path, evidence: dict[str, Any]) -> Path:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("filename", "outcome"),
    [
        ("service-no-ready-endpoints.json", "finding"),
        ("service-with-ready-endpoint.json", "no_finding"),
        ("service-selector-matches-no-pods.json", "finding"),
        ("service-matching-pods-not-ready.json", "finding"),
    ],
)
def test_cli_checked_in_fixture_outcomes(filename: str, outcome: str, capsys) -> None:
    exit_status = main([str(FIXTURES / filename)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_status == 0
    assert payload["schemaVersion"] == "kubetrace.report/v2"
    assert payload["outcome"] == outcome
    assert "SERVICE_NO_READY_ENDPOINTS" in captured.err


def test_cli_inconclusive_exit_status(tmp_path: Path, capsys) -> None:
    evidence = load_fixture()
    evidence["collection"]["status"] = "incomplete"

    exit_status = main([str(write_fixture(tmp_path, evidence))])

    assert exit_status == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "inconclusive"


def test_cli_not_applicable_exit_status(tmp_path: Path, capsys) -> None:
    evidence = load_fixture()
    evidence["service"]["spec"] = {
        "type": "ExternalName",
        "externalName": "example.invalid",
    }

    exit_status = main([str(write_fixture(tmp_path, evidence))])

    assert exit_status == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "not_applicable"


def test_cli_malformed_json_has_error_shape_and_nonzero_status(
    tmp_path: Path, capsys
) -> None:
    fixture = tmp_path / "malformed.json"
    fixture.write_text("{not-json", encoding="utf-8")

    exit_status = main([str(fixture)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_status == 2
    assert payload["outcome"] == "validation_error"
    assert payload["service"] is None
    assert payload["errors"]
    assert payload["observedEvidence"] == []
    assert "VALIDATION_ERROR" in captured.err


def test_cli_structurally_invalid_input_is_nonzero(tmp_path: Path, capsys) -> None:
    fixture = write_fixture(tmp_path, {})

    exit_status = main([str(fixture)])

    captured = capsys.readouterr()
    assert exit_status == 2
    assert json.loads(captured.out)["outcome"] == "validation_error"


def test_cli_missing_path_is_nonzero_and_terminal_safe(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.json"

    exit_status = main([str(missing)])

    captured = capsys.readouterr()
    assert exit_status == 2
    assert json.loads(captured.out)["outcome"] == "validation_error"
    assert "cannot read fixture" in captured.err


def test_cli_output_is_deterministic(tmp_path: Path, capsys) -> None:
    evidence = load_fixture()
    reordered = deepcopy(evidence)
    reordered["endpointSliceList"]["items"].reverse()
    fixture = write_fixture(tmp_path, reordered)

    assert main([str(fixture)]) == 0
    first = capsys.readouterr()
    assert main([str(fixture)]) == 0
    second = capsys.readouterr()

    assert first.out == second.out
    assert first.err == second.err


def test_explicit_fixture_mode_preserves_fixture_pipeline(capsys) -> None:
    exit_status = main(["fixture", str(FIXTURES / "service-no-ready-endpoints.json")])

    payload = json.loads(capsys.readouterr().out)
    assert exit_status == 0
    assert payload["outcome"] == "finding"


def test_fixture_mode_never_initializes_kubernetes(capsys) -> None:
    def unexpected_factory(*_args: Any) -> _KubernetesSession:
        pytest.fail("fixture mode initialized Kubernetes")

    exit_status = main(
        [str(FIXTURES / "service-with-ready-endpoint.json")],
        kubernetes_session_factory=unexpected_factory,
    )

    assert exit_status == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "no_finding"


def test_kubernetes_mode_uses_target_and_shared_pipeline(capsys) -> None:
    evidence = load_fixture()
    evidence["collection"]["source"] = "kubernetes-api"
    calls: list[tuple[str, str, str | None, str | None]] = []
    closed: list[bool] = []

    def session_factory(
        namespace: str,
        service_name: str,
        kubeconfig: str | None,
        context: str | None,
    ) -> _KubernetesSession:
        calls.append((namespace, service_name, kubeconfig, context))
        return _KubernetesSession(
            collector=StaticCollector(evidence),
            close=lambda: closed.append(True),
        )

    exit_status = main(
        [
            "kubernetes",
            "--namespace",
            "shop",
            "--service",
            "checkout",
            "--kubeconfig",
            "test-config",
            "--context",
            "test-context",
        ],
        kubernetes_session_factory=session_factory,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_status == 0
    assert calls == [("shop", "checkout", "test-config", "test-context")]
    assert closed == [True]
    assert payload["outcome"] == "finding"
    assert payload["target"] == {"namespace": "shop", "serviceName": "checkout"}
    assert payload["observedEvidence"][0]["source"] == "kubernetes-api"


def test_kubernetes_setup_failure_is_sanitized_and_inconclusive(capsys) -> None:
    def session_factory(
        _namespace: str,
        _service_name: str,
        _kubeconfig: str | None,
        _context: str | None,
    ) -> _KubernetesSession:
        raise _KubernetesSetupError(
            "configuration_error",
            "Kubernetes client configuration failed.",
        ) from RuntimeError("token=secret-value")

    exit_status = main(
        ["kubernetes", "--namespace", "shop", "--service", "checkout"],
        kubernetes_session_factory=session_factory,
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_status == 0
    assert payload["outcome"] == "inconclusive"
    assert payload["service"] is None
    assert payload["collectionIssues"] == [
        {
            "operation": "configure_client",
            "code": "configuration_error",
            "message": "Kubernetes client configuration failed.",
            "status": None,
        }
    ]
    assert "secret-value" not in captured.out
    assert "secret-value" not in captured.err


def test_kubernetes_session_loads_config_without_persistence(monkeypatch) -> None:
    config_calls: list[dict[str, Any]] = []
    api_client = SimpleNamespace(closed=False)
    api_client.close = lambda: setattr(api_client, "closed", True)
    core_api = object()
    discovery_api = object()

    kubernetes = ModuleType("kubernetes")
    kubernetes.config = SimpleNamespace(
        load_kube_config=lambda **kwargs: config_calls.append(kwargs)
    )
    kubernetes.client = SimpleNamespace(
        ApiClient=lambda: api_client,
        CoreV1Api=lambda value: core_api if value is api_client else None,
        DiscoveryV1Api=lambda value: discovery_api if value is api_client else None,
    )
    monkeypatch.setitem(sys.modules, "kubernetes", kubernetes)

    session = _create_kubernetes_session(
        "shop", "checkout", "test-config", "test-context"
    )

    assert config_calls == [
        {
            "persist_config": False,
            "config_file": "test-config",
            "context": "test-context",
        }
    ]
    assert session.collector.core_api is core_api
    assert session.collector.discovery_api is discovery_api
    assert session.collector.namespace == "shop"
    assert session.collector.service_name == "checkout"
    session.close()
    assert api_client.closed is True


def test_kubernetes_mode_runs_with_mocked_config_and_api_clients(
    monkeypatch, capsys
) -> None:
    config_calls: list[dict[str, Any]] = []
    service_calls: list[dict[str, Any]] = []
    pod_calls: list[dict[str, Any]] = []
    slice_calls: list[dict[str, Any]] = []
    api_client = SimpleNamespace(closed=False)
    api_client.close = lambda: setattr(api_client, "closed", True)

    service = SimpleNamespace(
        api_version="v1",
        kind="Service",
        metadata=SimpleNamespace(
            namespace="shop",
            name="checkout",
            uid="service-checkout",
        ),
        spec=SimpleNamespace(
            type="ClusterIP",
            selector={"app": "checkout"},
            external_name=None,
        ),
    )
    endpoint_slice_page = SimpleNamespace(
        api_version="discovery.k8s.io/v1",
        kind="EndpointSliceList",
        metadata=SimpleNamespace(resource_version="100", _continue=""),
        items=[],
    )
    pod_page = SimpleNamespace(
        api_version="v1",
        kind="PodList",
        metadata=SimpleNamespace(resource_version="200", _continue=""),
        items=[],
    )

    class CoreApi:
        def read_namespaced_service(self, **kwargs: Any) -> Any:
            service_calls.append(kwargs)
            return service

        def list_namespaced_pod(self, **kwargs: Any) -> Any:
            pod_calls.append(kwargs)
            return pod_page

    class DiscoveryApi:
        def list_namespaced_endpoint_slice(self, **kwargs: Any) -> Any:
            slice_calls.append(kwargs)
            return endpoint_slice_page

    kubernetes = ModuleType("kubernetes")
    kubernetes.config = SimpleNamespace(
        load_kube_config=lambda **kwargs: config_calls.append(kwargs)
    )
    kubernetes.client = SimpleNamespace(
        ApiClient=lambda: api_client,
        CoreV1Api=lambda value: CoreApi() if value is api_client else None,
        DiscoveryV1Api=lambda value: DiscoveryApi() if value is api_client else None,
    )
    monkeypatch.setitem(sys.modules, "kubernetes", kubernetes)

    exit_status = main(
        [
            "kubernetes",
            "--namespace",
            "shop",
            "--service",
            "checkout",
            "--context",
            "test-context",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_status == 0
    assert payload["outcome"] == "finding"
    assert config_calls == [{"persist_config": False, "context": "test-context"}]
    assert service_calls == [
        {"name": "checkout", "namespace": "shop", "_request_timeout": (3.0, 10.0)}
    ]
    assert slice_calls == [
        {
            "namespace": "shop",
            "label_selector": "kubernetes.io/service-name=checkout",
            "limit": 100,
            "_request_timeout": (3.0, 10.0),
        }
    ]
    assert pod_calls == [
        {
            "namespace": "shop",
            "label_selector": "",
            "limit": 100,
            "_request_timeout": (3.0, 10.0),
        }
    ]
    assert api_client.closed is True


def test_kubernetes_configuration_exception_does_not_leak_details(
    monkeypatch,
) -> None:
    def fail_to_load(**_kwargs: Any) -> None:
        raise RuntimeError("client-certificate-data: secret-value")

    kubernetes = ModuleType("kubernetes")
    kubernetes.config = SimpleNamespace(load_kube_config=fail_to_load)
    kubernetes.client = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "kubernetes", kubernetes)

    with pytest.raises(_KubernetesSetupError) as raised:
        _create_kubernetes_session("shop", "checkout", None, None)

    assert raised.value.code == "configuration_error"
    assert str(raised.value) == "Kubernetes client configuration failed."
    assert "secret-value" not in str(raised.value)
