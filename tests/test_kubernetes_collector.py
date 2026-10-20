from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from kubetrace.engine import run_diagnostic
from kubetrace.kubernetes_collector import CollectionBudgets, KubernetesCollector
from kubetrace.models import Outcome
from kubetrace.reporting import report_payload, to_json

NOW = datetime(2026, 10, 20, 8, 30, tzinfo=UTC)
TIMEOUT = (1.0, 2.0)
SELECTOR = "kubernetes.io/service-name=checkout"


class StaticCollector:
    def __init__(self, evidence: dict[str, Any]) -> None:
        self.evidence = evidence

    def collect(self) -> dict[str, Any]:
        return self.evidence


def diagnose(evidence: dict[str, Any]):
    return run_diagnostic(StaticCollector(evidence))


class FakeApiError(Exception):
    def __init__(
        self, status: int, sensitive_text: str = "secret response body"
    ) -> None:
        self.status = status
        super().__init__(sensitive_text)


class FakeCoreApi:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def read_namespaced_service(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class FakeDiscoveryApi:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = iter(responses)
        self.calls: list[dict[str, Any]] = []

    def list_namespaced_endpoint_slice(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def service(
    *, service_type: str = "ClusterIP", external_name: str | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        api_version="v1",
        kind="Service",
        metadata=SimpleNamespace(
            namespace="shop",
            name="checkout",
            uid="service-uid",
            annotations={"credential": "must-not-be-collected"},
            resource_version="service-rv",
        ),
        spec=SimpleNamespace(
            type=service_type,
            selector=None if service_type == "ExternalName" else {"app": "checkout"},
            external_name=external_name,
            ports=[SimpleNamespace(port=443)],
        ),
        status=SimpleNamespace(load_balancer="not-collected"),
    )


def endpoint(address: str, ready: bool | None) -> SimpleNamespace:
    return SimpleNamespace(
        addresses=[address],
        conditions=SimpleNamespace(ready=ready),
        target_ref=SimpleNamespace(name="must-not-be-collected"),
        node_name="must-not-be-collected",
    )


def endpoint_slice(
    name: str,
    endpoints: list[SimpleNamespace],
    *,
    address_type: str = "IPv4",
) -> SimpleNamespace:
    return SimpleNamespace(
        api_version="discovery.k8s.io/v1",
        kind="EndpointSlice",
        address_type=address_type,
        metadata=SimpleNamespace(
            namespace="shop",
            name=name,
            labels={
                "kubernetes.io/service-name": "checkout",
                "sensitive.example/label": "must-not-be-collected",
            },
            annotations={"credential": "must-not-be-collected"},
        ),
        endpoints=endpoints,
        ports=[SimpleNamespace(port=443)],
    )


def page(
    resource_version: str | None,
    continuation: str,
    items: list[SimpleNamespace],
) -> SimpleNamespace:
    return SimpleNamespace(
        api_version="discovery.k8s.io/v1",
        kind="EndpointSliceList",
        metadata=SimpleNamespace(
            resource_version=resource_version,
            _continue=continuation,
        ),
        items=items,
    )


def collector(
    responses: list[Any],
    *,
    core_response: Any | None = None,
    budgets: CollectionBudgets | None = None,
    monotonic_clock=lambda: 0.0,
) -> tuple[KubernetesCollector, FakeCoreApi, FakeDiscoveryApi]:
    core = FakeCoreApi(service() if core_response is None else core_response)
    discovery = FakeDiscoveryApi(responses)
    instance = KubernetesCollector(
        core,
        discovery,
        "shop",
        "checkout",
        lambda: NOW,
        page_size=2,
        request_timeout=TIMEOUT,
        budgets=budgets,
        monotonic_clock=monotonic_clock,
    )
    return instance, core, discovery


def issue_code(evidence: dict[str, Any]) -> str:
    return evidence["collection"]["issues"][0]["code"]


def test_single_page_collection_uses_exact_read_only_arguments() -> None:
    instance, core, discovery = collector([page("100", "", [])])

    evidence = dict(instance.collect())

    assert core.calls == [
        {
            "name": "checkout",
            "namespace": "shop",
            "_request_timeout": TIMEOUT,
        }
    ]
    assert discovery.calls == [
        {
            "namespace": "shop",
            "label_selector": SELECTOR,
            "limit": 2,
            "_request_timeout": TIMEOUT,
        }
    ]
    assert evidence["collection"]["status"] == "complete"
    assert evidence["collection"]["endpointSliceListRequest"] == {
        "namespace": "shop",
        "labelSelector": SELECTOR,
    }
    assert evidence["endpointSliceList"]["metadata"] == {
        "resourceVersion": "100",
        "continue": "",
    }


def test_multi_page_collection_preserves_query_and_follows_tokens() -> None:
    first = endpoint_slice("checkout-b", [endpoint("10.0.0.2", False)])
    second = endpoint_slice("checkout-a", [endpoint("10.0.0.1", True)])
    instance, _, discovery = collector(
        [page("100", "token-1", [first]), page("100", "", [second])]
    )

    evidence = dict(instance.collect())

    assert discovery.calls == [
        {
            "namespace": "shop",
            "label_selector": SELECTOR,
            "limit": 2,
            "_request_timeout": TIMEOUT,
        },
        {
            "namespace": "shop",
            "label_selector": SELECTOR,
            "limit": 2,
            "_request_timeout": TIMEOUT,
            "_continue": "token-1",
        },
    ]
    assert [
        item["metadata"]["name"] for item in evidence["endpointSliceList"]["items"]
    ] == ["checkout-a", "checkout-b"]
    assert diagnose(evidence).outcome is Outcome.NO_FINDING


def test_empty_complete_list_flows_to_finding() -> None:
    instance, _, _ = collector([page("100", "", [])])

    report = run_diagnostic(instance)

    assert report.outcome is Outcome.FINDING
    assert report.rule_id == "SERVICE_NO_READY_ENDPOINTS"


def test_resource_version_mismatch_is_inconclusive() -> None:
    instance, _, _ = collector([page("100", "next", []), page("101", "", [])])

    evidence = dict(instance.collect())
    report = diagnose(evidence)

    assert issue_code(evidence) == "resource_version_mismatch"
    assert evidence["collection"]["status"] == "incomplete"
    assert report.outcome is Outcome.INCONCLUSIVE


@pytest.mark.parametrize(
    ("resource_version", "expected_code"),
    [("", "missing_resource_version"), (None, "invalid_response")],
)
def test_missing_resource_version_is_inconclusive(
    resource_version: str | None, expected_code: str
) -> None:
    instance, _, _ = collector([page(resource_version, "", [])])

    evidence = dict(instance.collect())

    assert issue_code(evidence) == expected_code
    assert diagnose(evidence).outcome is Outcome.INCONCLUSIVE


def test_repeated_continuation_token_is_inconclusive() -> None:
    instance, _, _ = collector([page("100", "same", []), page("100", "same", [])])

    evidence = dict(instance.collect())

    assert issue_code(evidence) == "repeated_continue_token"
    assert diagnose(evidence).outcome is Outcome.INCONCLUSIVE


@pytest.mark.parametrize(
    ("budgets", "responses", "expected_code"),
    [
        (
            CollectionBudgets(max_pages=1),
            [page("100", "next", [])],
            "page_limit",
        ),
        (
            CollectionBudgets(max_endpoint_slices=0),
            [page("100", "", [endpoint_slice("checkout-a", [])])],
            "slice_limit",
        ),
        (
            CollectionBudgets(max_endpoints=0),
            [
                page(
                    "100",
                    "",
                    [endpoint_slice("checkout-a", [endpoint("10.0.0.1", False)])],
                )
            ],
            "endpoint_limit",
        ),
    ],
)
def test_cardinality_budgets_are_inconclusive(
    budgets: CollectionBudgets, responses: list[Any], expected_code: str
) -> None:
    instance, _, _ = collector(responses, budgets=budgets)

    evidence = dict(instance.collect())

    assert issue_code(evidence) == expected_code
    assert diagnose(evidence).outcome is Outcome.INCONCLUSIVE


def test_elapsed_time_budget_is_inconclusive() -> None:
    times: Iterator[float] = iter([0.0, 0.0, 0.0, 0.0, 2.0, 2.0])
    instance, _, _ = collector(
        [page("100", "", [])],
        budgets=CollectionBudgets(max_elapsed_seconds=1.0),
        monotonic_clock=lambda: next(times),
    )

    evidence = dict(instance.collect())

    assert issue_code(evidence) == "timeout"
    assert diagnose(evidence).outcome is Outcome.INCONCLUSIVE


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (FakeApiError(401), "unauthorized"),
        (FakeApiError(403), "forbidden"),
        (FakeApiError(404), "not_found"),
        (FakeApiError(410), "pagination_expired"),
        (FakeApiError(0), "transport_error"),
        (TimeoutError("sensitive timeout detail"), "timeout"),
        (OSError("sensitive transport detail"), "transport_error"),
    ],
)
def test_api_and_transport_failures_are_sanitized_and_inconclusive(
    error: Exception, expected_code: str
) -> None:
    instance, _, _ = collector([error])

    evidence = dict(instance.collect())
    serialized = json.dumps(evidence)
    report = diagnose(evidence)

    assert issue_code(evidence) == expected_code
    assert evidence["collection"]["status"] == "incomplete"
    assert "sensitive" not in serialized
    assert "secret response body" not in serialized
    assert report.outcome is Outcome.INCONCLUSIVE


def test_service_failure_has_explicit_target_without_fabricated_service() -> None:
    instance, _, discovery = collector([], core_response=FakeApiError(403))

    evidence = dict(instance.collect())
    payload = report_payload(diagnose(evidence))

    assert "service" not in evidence
    assert discovery.calls == []
    assert payload["schemaVersion"] == "kubetrace.report/v2"
    assert payload["target"] == {
        "namespace": "shop",
        "serviceName": "checkout",
    }
    assert payload["service"] is None
    assert payload["outcome"] == "inconclusive"
    assert payload["collectionIssues"] == [
        {
            "operation": "read_service",
            "code": "forbidden",
            "message": "Kubernetes API authorization was denied.",
            "status": 403,
        }
    ]


def test_failure_after_successful_page_never_uses_partial_evidence() -> None:
    partial = endpoint_slice("checkout-a", [endpoint("10.0.0.1", True)])
    instance, _, _ = collector([page("100", "next", [partial]), FakeApiError(403)])

    evidence = dict(instance.collect())
    report = diagnose(evidence)

    assert evidence["endpointSliceList"]["metadata"]["continue"] == "next"
    assert issue_code(evidence) == "forbidden"
    assert report.outcome is Outcome.INCONCLUSIVE
    assert report.derived_findings == ()


def test_projection_is_minimal_and_omits_unrelated_metadata() -> None:
    item = endpoint_slice("checkout-a", [endpoint("10.0.0.1", False)])
    instance, _, _ = collector([page("100", "", [item])])

    evidence = dict(instance.collect())
    serialized = json.dumps(evidence)

    assert "annotations" not in serialized
    assert "must-not-be-collected" not in serialized
    assert "target_ref" not in serialized
    assert "node_name" not in serialized
    assert "ports" not in serialized
    assert "status" not in evidence["service"]
    assert set(evidence["service"]["metadata"]) == {"namespace", "name", "uid"}
    assert set(evidence["endpointSliceList"]["items"][0]["metadata"]["labels"]) == {
        "kubernetes.io/service-name"
    }


@pytest.mark.parametrize(
    ("ready", "expected"),
    [
        (True, Outcome.NO_FINDING),
        (False, Outcome.FINDING),
        (None, Outcome.INCONCLUSIVE),
    ],
)
def test_readiness_values_use_shared_rule(
    ready: bool | None, expected: Outcome
) -> None:
    item = endpoint_slice("checkout-a", [endpoint("10.0.0.1", ready)])
    instance, _, _ = collector([page("100", "", [item])])

    assert run_diagnostic(instance).outcome is expected


def test_external_name_skips_endpoint_slice_collection() -> None:
    external = service(service_type="ExternalName", external_name="api.example.test")
    instance, _, discovery = collector([], core_response=external)

    report = run_diagnostic(instance)

    assert report.outcome is Outcome.NOT_APPLICABLE
    assert discovery.calls == []


@pytest.mark.parametrize(
    "malformed",
    [
        SimpleNamespace(api_version="v1", kind="Service", metadata=None, spec=None),
        SimpleNamespace(
            api_version="v1",
            kind="Service",
            metadata=SimpleNamespace(namespace="shop", name="checkout", uid=None),
            spec=SimpleNamespace(type="ClusterIP", selector={"app": "checkout"}),
        ),
    ],
)
def test_malformed_service_response_is_inconclusive(malformed: Any) -> None:
    instance, _, _ = collector([], core_response=malformed)

    evidence = dict(instance.collect())

    assert issue_code(evidence) == "invalid_response"
    assert diagnose(evidence).outcome is Outcome.INCONCLUSIVE


def test_malformed_endpoint_slice_page_is_inconclusive() -> None:
    malformed = SimpleNamespace(metadata=None, items=None)
    instance, _, _ = collector([malformed])

    evidence = dict(instance.collect())

    assert issue_code(evidence) == "invalid_response"
    assert diagnose(evidence).outcome is Outcome.INCONCLUSIVE


def test_projection_and_report_are_deterministic() -> None:
    first = endpoint_slice(
        "checkout-b",
        [endpoint("10.0.0.2", False), endpoint("10.0.0.1", False)],
    )
    second = endpoint_slice("checkout-a", [endpoint("10.0.0.3", False)])
    collector_one, _, _ = collector([page("100", "", [first, second])])
    collector_two, _, _ = collector([page("100", "", [second, first])])

    first_evidence = collector_one.collect()
    second_evidence = collector_two.collect()

    assert first_evidence == second_evidence
    assert to_json(report_payload(diagnose(dict(first_evidence)))) == to_json(
        report_payload(diagnose(dict(second_evidence)))
    )
