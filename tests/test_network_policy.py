from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from kubetrace.engine import EvidenceValidationError, normalize, run_diagnostic
from kubetrace.kubernetes_collector import CollectionBudgets, KubernetesCollector
from kubetrace.models import Outcome
from kubetrace.reporting import report_payload, to_json

FIXTURES = Path(__file__).parents[1] / "fixtures"


class StaticCollector:
    def __init__(self, evidence: dict[str, Any]) -> None:
        self.evidence = evidence

    def collect(self) -> dict[str, Any]:
        return self.evidence


def evidence() -> dict[str, Any]:
    value = json.loads(
        (FIXTURES / "service-matching-pods-not-ready.json").read_text(encoding="utf-8")
    )
    value["podList"]["items"][0]["metadata"]["labels"]["role"] = "frontend"
    value["collection"]["podListCollection"]["request"]["projectedLabelKeys"] = [
        "app",
        "disabled",
        "role",
    ]
    return value


def selector(**labels: str) -> dict[str, Any]:
    return {"matchLabels": labels, "matchExpressions": []}


def policy(
    name: str,
    *,
    pod_selector: dict[str, Any] | None = None,
    policy_types: list[str] | None = None,
    ingress: list[dict[str, Any]] | None = None,
    egress: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "podSelector": pod_selector or selector(app="checkout"),
        "ingress": ingress or [],
        "egress": egress or [],
    }
    if policy_types is not None:
        spec["policyTypes"] = policy_types
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "namespace": "shop",
            "name": name,
            "uid": f"policy-{name}",
        },
        "spec": spec,
    }


def add_policies(
    value: dict[str, Any],
    policies: list[dict[str, Any]] | None,
    *,
    status: str = "complete",
    issues: list[dict[str, Any]] | None = None,
) -> None:
    collection: dict[str, Any] = {
        "status": status,
        "request": {"namespace": "shop"},
    }
    if issues:
        collection["issues"] = issues
    value["collection"]["networkPolicyListCollection"] = collection
    if policies is not None:
        value["networkPolicyList"] = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicyList",
            "metadata": {"resourceVersion": "300", "continue": ""},
            "items": policies,
        }


def add_traffic(
    value: dict[str, Any],
    direction: str,
    *,
    protocol: str = "TCP",
    port: int = 443,
    namespace: str | None = "client",
    namespace_labels: dict[str, str] | None = None,
    pod_labels: dict[str, str] | None = None,
    ip: str | None = None,
) -> None:
    peer: dict[str, Any] = {}
    if namespace is not None:
        peer["namespace"] = namespace
    if namespace_labels is not None:
        peer["namespaceLabels"] = namespace_labels
    if pod_labels is not None:
        peer["podLabels"] = pod_labels
    if ip is not None:
        peer["ip"] = ip
    value["traffic"] = {
        "direction": direction,
        "protocol": protocol,
        "port": port,
        "peer": peer,
    }


def diagnose(value: dict[str, Any]):
    return run_diagnostic(StaticCollector(value))


def allow_rule(
    peer: dict[str, Any] | None = None,
    *,
    port: int = 443,
    protocol: str = "TCP",
    direction: str = "ingress",
) -> dict[str, Any]:
    return {
        "from" if direction == "ingress" else "to": [peer] if peer else [],
        "ports": [{"protocol": protocol, "port": port}],
    }


def test_checked_in_network_policy_fixture_uses_shared_pipeline() -> None:
    report = run_diagnostic(
        StaticCollector(
            json.loads(
                (
                    FIXTURES / "service-networkpolicy-ingress-default-deny.json"
                ).read_text(encoding="utf-8")
            )
        )
    )

    assert report.outcome is Outcome.FINDING
    assert any("does not allow" in item for item in report.derived_findings)
    assert not any("NetworkPolicy" in item for item in report.confirmed_causes)


def test_no_network_policies_reports_no_isolation() -> None:
    value = evidence()
    add_policies(value, [])

    report = diagnose(value)

    assert report.outcome is Outcome.FINDING
    assert any("ingress isolation and 0/1" in item for item in report.derived_findings)
    assert not any(
        "NetworkPolicies may restrict" in item for item in report.possible_causes
    )


def test_policy_analysis_is_independent_of_ready_endpoint_rule_outcome() -> None:
    value = evidence()
    value["endpointSliceList"]["items"][0]["endpoints"][0]["conditions"]["ready"] = True
    add_policies(value, [policy("deny-ingress", policy_types=["Ingress"])])
    add_traffic(value, "ingress")

    report = diagnose(value)

    assert report.outcome is Outcome.NO_FINDING
    assert any("does not allow" in item for item in report.derived_findings)
    assert report.confirmed_causes == ()


def test_policy_without_traffic_context_reports_only_possible_restriction() -> None:
    value = evidence()
    add_policies(value, [policy("deny-ingress", policy_types=["Ingress"])])

    report = diagnose(value)

    assert any("NetworkPolicy selects" in item for item in report.derived_findings)
    assert any("may restrict" in item for item in report.possible_causes)
    assert any("Source or destination" in item for item in report.limitations)
    assert not any("NetworkPolicy" in item for item in report.confirmed_causes)


@pytest.mark.parametrize("direction", ["ingress", "egress"])
def test_default_deny_is_a_possible_restriction_not_confirmed_cause(
    direction: str,
) -> None:
    value = evidence()
    add_policies(
        value,
        [policy(f"deny-{direction}", policy_types=[direction.capitalize()])],
    )
    add_traffic(value, direction)

    report = diagnose(value)

    assert any("does not allow" in item for item in report.derived_findings)
    assert "NetworkPolicy enforcement may restrict" in report.possible_causes[-1]
    assert not any("NetworkPolicy" in item for item in report.confirmed_causes)
    assert any("do not prove" in item for item in report.limitations)


def test_multiple_policy_rules_are_unioned_to_allow_traffic() -> None:
    value = evidence()
    add_policies(
        value,
        [
            policy("deny", policy_types=["Ingress"]),
            policy(
                "allow",
                policy_types=["Ingress"],
                ingress=[allow_rule()],
            ),
        ],
    )
    add_traffic(value, "ingress")

    report = diagnose(value)

    assert any("allows the described" in item for item in report.derived_findings)
    assert not any(
        "NetworkPolicy enforcement" in item for item in report.possible_causes
    )


def test_policy_target_selector_mismatch_does_not_isolate_service_pod() -> None:
    value = evidence()
    add_policies(
        value,
        [
            policy(
                "other-pods",
                pod_selector=selector(role="worker"),
                policy_types=["Ingress"],
            )
        ],
    )
    add_traffic(value, "ingress")

    report = diagnose(value)

    assert any(
        "0/1 Service Pods for ingress" in item for item in report.derived_findings
    )
    assert any("allows the described" in item for item in report.derived_findings)


def test_policy_match_expressions_follow_kubernetes_selector_semantics() -> None:
    value = evidence()
    expression_selector = {
        "matchLabels": {"app": "checkout"},
        "matchExpressions": [
            {"key": "role", "operator": "In", "values": ["frontend"]},
            {"key": "disabled", "operator": "DoesNotExist", "values": []},
        ],
    }
    add_policies(
        value,
        [
            policy(
                "expressions",
                pod_selector=expression_selector,
                policy_types=["Ingress"],
            )
        ],
    )
    add_traffic(value, "ingress")

    report = diagnose(value)

    assert any(
        "1/1 Service Pods for ingress" in item for item in report.derived_findings
    )


def test_namespace_selector_mismatch_does_not_allow_peer() -> None:
    value = evidence()
    rule = allow_rule({"namespaceSelector": selector(team="trusted")})
    add_policies(
        value,
        [policy("trusted-only", policy_types=["Ingress"], ingress=[rule])],
    )
    add_traffic(value, "ingress", namespace_labels={"team": "other"})

    assert any("does not allow" in item for item in diagnose(value).derived_findings)


def test_empty_namespace_selector_matches_without_namespace_labels() -> None:
    value = evidence()
    rule = allow_rule({"namespaceSelector": selector()})
    add_policies(
        value,
        [policy("all-namespaces", policy_types=["Ingress"], ingress=[rule])],
    )
    add_traffic(value, "ingress", namespace_labels=None)

    assert any(
        "allows the described" in item for item in diagnose(value).derived_findings
    )


def test_combined_namespace_and_pod_selectors_both_must_match() -> None:
    value = evidence()
    peer = {
        "namespaceSelector": selector(team="trusted"),
        "podSelector": selector(app="client"),
    }
    add_policies(
        value,
        [
            policy(
                "combined",
                policy_types=["Ingress"],
                ingress=[allow_rule(peer)],
            )
        ],
    )
    add_traffic(
        value,
        "ingress",
        namespace_labels={"team": "trusted"},
        pod_labels={"app": "client"},
    )
    allowed = diagnose(value)
    assert any("allows the described" in item for item in allowed.derived_findings)

    value["traffic"]["peer"]["podLabels"]["app"] = "other"
    denied = diagnose(value)
    assert any("does not allow" in item for item in denied.derived_findings)


def test_peer_pod_selector_without_namespace_selector_is_same_namespace_only() -> None:
    value = evidence()
    rule = allow_rule({"podSelector": selector(app="client")})
    add_policies(
        value,
        [policy("same-namespace", policy_types=["Ingress"], ingress=[rule])],
    )
    add_traffic(value, "ingress", namespace="other", pod_labels={"app": "client"})
    denied = diagnose(value)
    assert any("does not allow" in item for item in denied.derived_findings)

    value["traffic"]["peer"]["namespace"] = "shop"
    allowed = diagnose(value)
    assert any("allows the described" in item for item in allowed.derived_findings)


@pytest.mark.parametrize(("protocol", "port"), [("UDP", 443), ("TCP", 80)])
def test_port_and_protocol_restrictions(protocol: str, port: int) -> None:
    value = evidence()
    add_policies(
        value,
        [
            policy(
                "https-only",
                policy_types=["Ingress"],
                ingress=[allow_rule()],
            )
        ],
    )
    add_traffic(value, "ingress", protocol=protocol, port=port)

    assert any("does not allow" in item for item in diagnose(value).derived_findings)


def test_named_policy_port_remains_unresolved_without_container_port_mapping() -> None:
    value = evidence()
    named_port_rule = {
        "from": [],
        "ports": [{"protocol": "TCP", "port": "https"}],
    }
    add_policies(
        value,
        [
            policy(
                "named-port",
                policy_types=["Ingress"],
                ingress=[named_port_rule],
            )
        ],
    )
    add_traffic(value, "ingress", port=443)

    report = diagnose(value)

    assert not any("does not allow" in item for item in report.derived_findings)
    assert any("named ports" in item for item in report.limitations)


def test_numeric_end_port_range_allows_in_range_traffic() -> None:
    value = evidence()
    range_rule = {
        "from": [],
        "ports": [{"protocol": "TCP", "port": 440, "endPort": 445}],
    }
    add_policies(
        value,
        [policy("port-range", policy_types=["Ingress"], ingress=[range_rule])],
    )
    add_traffic(value, "ingress", port=443)

    assert any(
        "allows the described" in item for item in diagnose(value).derived_findings
    )


def test_ip_block_exception_excludes_peer() -> None:
    value = evidence()
    peer = {"ipBlock": {"cidr": "192.0.2.0/24", "except": ["192.0.2.128/25"]}}
    add_policies(
        value,
        [policy("ip-range", policy_types=["Ingress"], ingress=[allow_rule(peer)])],
    )
    add_traffic(value, "ingress", ip="192.0.2.200")

    assert any("does not allow" in item for item in diagnose(value).derived_findings)

    value["traffic"]["peer"]["ip"] = "192.0.2.20"
    assert any(
        "allows the described" in item for item in diagnose(value).derived_findings
    )


def test_missing_peer_information_is_unresolved() -> None:
    value = evidence()
    rule = allow_rule({"namespaceSelector": selector(team="trusted")})
    add_policies(
        value,
        [policy("trusted-only", policy_types=["Ingress"], ingress=[rule])],
    )
    add_traffic(value, "ingress", namespace_labels=None)

    report = diagnose(value)

    assert not any("does not allow" in item for item in report.derived_findings)
    assert any("unresolved" in item for item in report.limitations)


def test_missing_peer_identity_cannot_produce_policy_spec_deny() -> None:
    value = evidence()
    add_policies(value, [policy("deny-ingress", policy_types=["Ingress"])])
    add_traffic(value, "ingress", namespace=None)

    report = diagnose(value)

    assert not any("does not allow" in item for item in report.derived_findings)
    assert any("identity is missing" in item for item in report.limitations)
    assert not any("NetworkPolicy" in item for item in report.confirmed_causes)


def test_incomplete_policy_collection_and_rbac_error_cannot_support_conclusion() -> (
    None
):
    value = evidence()
    add_policies(
        value,
        None,
        status="incomplete",
        issues=[
            {
                "operation": "list_network_policies",
                "code": "forbidden",
                "message": "Kubernetes API authorization was denied.",
                "status": 403,
            }
        ],
    )

    report = diagnose(value)

    assert report.outcome is Outcome.FINDING
    assert report.confirmed_causes == (
        "All 1 Pods matching the Service selector explicitly reported Ready=False "
        "during the bounded collection.",
    )
    assert any(issue.code == "forbidden" for issue in report.collection_issues)
    assert any("evidence is incomplete" in item for item in report.limitations)


def test_duplicate_policy_identity_cannot_support_policy_conclusion() -> None:
    value = evidence()
    item = policy("deny", policy_types=["Ingress"])
    duplicate = deepcopy(item)
    duplicate["metadata"]["uid"] = "different-uid"
    add_policies(value, [item, duplicate])

    report = diagnose(value)

    assert any("identities are duplicated" in item for item in report.limitations)
    assert not any("NetworkPolicy selects" in item for item in report.derived_findings)


def test_network_policy_report_is_deterministic_when_policies_are_reordered() -> None:
    value = evidence()
    add_policies(
        value,
        [
            policy("deny", policy_types=["Ingress"]),
            policy("allow", policy_types=["Ingress"], ingress=[allow_rule()]),
        ],
    )
    add_traffic(value, "ingress")
    reordered = deepcopy(value)
    reordered["networkPolicyList"]["items"].reverse()

    assert to_json(report_payload(diagnose(value))) == to_json(
        report_payload(diagnose(reordered))
    )


def test_malformed_or_contradictory_policy_evidence_is_rejected() -> None:
    value = evidence()
    malformed = policy(
        "bad",
        policy_types=["Ingress", "Ingress"],
        ingress=[
            allow_rule(
                {
                    "podSelector": selector(app="client"),
                    "ipBlock": {"cidr": "192.0.2.0/24", "except": []},
                }
            )
        ],
    )
    add_policies(value, [malformed])

    with pytest.raises(EvidenceValidationError):
        normalize(value)


class FakeApiError(Exception):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__("sensitive response body")


class FakeCoreApi:
    def read_namespaced_service(self, **_kwargs: Any) -> Any:
        return SimpleNamespace(
            api_version="v1",
            kind="Service",
            metadata=SimpleNamespace(
                namespace="shop", name="checkout", uid="service-checkout"
            ),
            spec=SimpleNamespace(
                type="ClusterIP",
                selector={"app": "checkout"},
                external_name=None,
            ),
        )

    def list_namespaced_pod(self, **_kwargs: Any) -> Any:
        return SimpleNamespace(
            api_version="v1",
            kind="PodList",
            metadata=SimpleNamespace(resource_version="200", _continue=""),
            items=[
                SimpleNamespace(
                    api_version="v1",
                    kind="Pod",
                    metadata=SimpleNamespace(
                        namespace="shop",
                        name="checkout-a",
                        uid="pod-checkout-a",
                        labels={
                            "app": "checkout",
                            "role": "frontend",
                            "secret.example/token": "must-not-be-collected",
                        },
                    ),
                    status=SimpleNamespace(
                        conditions=[SimpleNamespace(type="Ready", status="False")]
                    ),
                )
            ],
        )


class FakeDiscoveryApi:
    def list_namespaced_endpoint_slice(self, **_kwargs: Any) -> Any:
        return SimpleNamespace(
            api_version="discovery.k8s.io/v1",
            kind="EndpointSliceList",
            metadata=SimpleNamespace(resource_version="100", _continue=""),
            items=[],
        )


class FakeNetworkingApi:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = iter(responses)
        self.calls: list[dict[str, Any]] = []

    def list_namespaced_network_policy(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def api_selector(**labels: str) -> SimpleNamespace:
    return SimpleNamespace(match_labels=labels, match_expressions=[])


def api_policy(name: str) -> SimpleNamespace:
    return SimpleNamespace(
        api_version="networking.k8s.io/v1",
        kind="NetworkPolicy",
        metadata=SimpleNamespace(
            namespace="shop",
            name=name,
            uid=f"policy-{name}",
            annotations={"token": "must-not-be-collected"},
        ),
        spec=SimpleNamespace(
            pod_selector=api_selector(role="frontend"),
            policy_types=["Ingress"],
            ingress=[],
            egress=[],
        ),
    )


def api_policy_with_ingress_rule(name: str) -> SimpleNamespace:
    item = api_policy(name)
    item.spec.ingress = [SimpleNamespace(from_=[], ports=[])]
    return item


def api_policy_with_port(name: str) -> SimpleNamespace:
    item = api_policy(name)
    item.spec.ingress = [
        SimpleNamespace(
            from_=[],
            ports=[SimpleNamespace(protocol="TCP", port=443, end_port=None)],
        )
    ]
    return item


def policy_page(
    resource_version: str,
    continuation: str,
    items: list[SimpleNamespace],
) -> SimpleNamespace:
    return SimpleNamespace(
        api_version="networking.k8s.io/v1",
        kind="NetworkPolicyList",
        metadata=SimpleNamespace(
            resource_version=resource_version, _continue=continuation
        ),
        items=items,
    )


def live_collector(
    responses: list[Any], *, budgets: CollectionBudgets | None = None
) -> tuple[KubernetesCollector, FakeNetworkingApi]:
    networking = FakeNetworkingApi(responses)
    return (
        KubernetesCollector(
            FakeCoreApi(),
            FakeDiscoveryApi(),
            "shop",
            "checkout",
            lambda: datetime(2026, 10, 26, tzinfo=UTC),
            networking_api=networking,
            page_size=2,
            request_timeout=(1.0, 2.0),
            budgets=budgets,
            monotonic_clock=lambda: 0.0,
        ),
        networking,
    )


def test_network_policy_collector_paginates_and_projects_minimal_fields() -> None:
    collector, networking = live_collector(
        [
            policy_page("300", "next", [api_policy("deny-b")]),
            policy_page("300", "", [api_policy("deny-a")]),
        ]
    )

    collected = dict(collector.collect())
    serialized = json.dumps(collected)

    assert networking.calls == [
        {"namespace": "shop", "limit": 2, "_request_timeout": (1.0, 2.0)},
        {
            "namespace": "shop",
            "limit": 2,
            "_request_timeout": (1.0, 2.0),
            "_continue": "next",
        },
    ]
    assert [
        item["metadata"]["name"] for item in collected["networkPolicyList"]["items"]
    ] == ["deny-a", "deny-b"]
    assert collected["collection"]["podListCollection"]["request"][
        "projectedLabelKeys"
    ] == ["app", "role"]
    assert "annotations" not in serialized
    assert "must-not-be-collected" not in serialized


def test_network_policy_projection_preserves_only_evaluation_fields() -> None:
    item = api_policy("rules")
    item.spec.policy_types = ["Ingress", "Egress"]
    item.spec.pod_selector = SimpleNamespace(
        match_labels={"app": "checkout"},
        match_expressions=[
            SimpleNamespace(key="role", operator="In", values=["frontend"])
        ],
    )
    item.spec.ingress = [
        SimpleNamespace(
            from_=[
                SimpleNamespace(
                    pod_selector=api_selector(app="caller"),
                    namespace_selector=api_selector(team="trusted"),
                    ip_block=None,
                )
            ],
            ports=[SimpleNamespace(protocol="TCP", port=443, end_port=445)],
        )
    ]
    item.spec.egress = [
        SimpleNamespace(
            to=[
                SimpleNamespace(
                    pod_selector=None,
                    namespace_selector=None,
                    ip_block=SimpleNamespace(
                        cidr="192.0.2.0/24", except_=["192.0.2.128/25"]
                    ),
                )
            ],
            ports=[SimpleNamespace(protocol="UDP", port=53, end_port=None)],
        )
    ]
    collector, _ = live_collector([policy_page("300", "", [item])])

    projected = collector.collect()["networkPolicyList"]["items"][0]

    assert projected["metadata"] == {
        "namespace": "shop",
        "name": "rules",
        "uid": "policy-rules",
    }
    assert projected["spec"]["podSelector"]["matchExpressions"] == [
        {"key": "role", "operator": "In", "values": ["frontend"]}
    ]
    assert projected["spec"]["ingress"][0] == {
        "from": [
            {
                "podSelector": selector(app="caller"),
                "namespaceSelector": selector(team="trusted"),
            }
        ],
        "ports": [{"protocol": "TCP", "port": 443, "endPort": 445}],
    }
    assert projected["spec"]["egress"][0] == {
        "to": [
            {
                "ipBlock": {
                    "cidr": "192.0.2.0/24",
                    "except": ["192.0.2.128/25"],
                }
            }
        ],
        "ports": [{"protocol": "UDP", "port": 53}],
    }


@pytest.mark.parametrize(
    ("responses", "budgets", "code"),
    [
        ([FakeApiError(403)], None, "forbidden"),
        ([TimeoutError("sensitive")], None, "timeout"),
        ([SimpleNamespace(metadata=None, items=None)], None, "invalid_response"),
        (
            [policy_page("300", "next", [])],
            CollectionBudgets(max_pages=1),
            "page_limit",
        ),
        (
            [policy_page("300", "same", []), policy_page("300", "same", [])],
            None,
            "repeated_continue_token",
        ),
        (
            [policy_page("300", "next", []), policy_page("301", "", [])],
            None,
            "resource_version_mismatch",
        ),
        (
            [policy_page("300", "", [api_policy("deny")])],
            CollectionBudgets(max_network_policies=0),
            "policy_limit",
        ),
        (
            [policy_page("300", "", [api_policy_with_ingress_rule("deny")])],
            CollectionBudgets(max_network_policy_rules=0),
            "rule_limit",
        ),
        (
            [policy_page("300", "", [api_policy_with_port("allow")])],
            CollectionBudgets(max_network_policy_rule_entries=0),
            "rule_entry_limit",
        ),
    ],
)
def test_network_policy_collection_failures_are_bounded_and_sanitized(
    responses: list[Any], budgets: CollectionBudgets | None, code: str
) -> None:
    collector, _ = live_collector(responses, budgets=budgets)

    collected = dict(collector.collect())
    report = run_diagnostic(StaticCollector(collected))

    policy_collection = collected["collection"]["networkPolicyListCollection"]
    assert policy_collection["status"] == "incomplete"
    assert policy_collection["issues"][0]["code"] == code
    assert "sensitive" not in json.dumps(collected)
    assert not any("NetworkPolicy selects" in item for item in report.derived_findings)


def test_network_policy_failure_after_page_does_not_use_partial_evidence() -> None:
    collector, _ = live_collector(
        [policy_page("300", "next", [api_policy("partial")]), FakeApiError(403)]
    )

    collected = dict(collector.collect())
    report = run_diagnostic(StaticCollector(collected))

    assert collected["networkPolicyList"]["metadata"]["continue"] == "next"
    assert report.outcome is Outcome.FINDING
    assert not any("NetworkPolicy selects" in item for item in report.derived_findings)
    assert any("evidence is incomplete" in item for item in report.limitations)
