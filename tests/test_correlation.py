from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from kubetrace.engine import run_diagnostic
from kubetrace.models import Outcome
from kubetrace.reporting import report_payload

FIXTURES = Path(__file__).parents[1] / "fixtures"


class StaticCollector:
    def __init__(self, evidence: dict[str, Any]) -> None:
        self.evidence = evidence

    def collect(self) -> dict[str, Any]:
        return self.evidence


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def diagnose(value: dict[str, Any]):
    return run_diagnostic(StaticCollector(value))


def add_flow_collection(
    value: dict[str, Any],
    flows: list[dict[str, Any]],
    *,
    start: str = "2026-10-26T11:59:00Z",
    end: str = "2026-10-26T12:00:00Z",
    status: str = "complete",
) -> None:
    collection: dict[str, Any] = {
        "status": status,
        "window": {"start": start, "end": end},
        "truncated": False,
        "issues": [],
    }
    if status == "incomplete":
        collection["issues"] = [
            {
                "operation": "observe_flows",
                "code": "timeout",
                "message": "Hubble observation timed out.",
                "status": None,
            }
        ]
    value["collection"]["hubbleFlowCollection"] = collection
    value["flows"] = flows


def relevant_flow(
    *,
    verdict: str = "DROPPED",
    policy_related: bool = True,
    timestamp: str = "2026-10-26T11:59:45Z",
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "verdict": verdict,
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
        "dropReason": "POLICY_DENIED" if policy_related else "CT_UNKNOWN",
        "policyRelated": policy_related,
    }


def test_successful_correlation_preserves_each_source_provenance() -> None:
    report = diagnose(fixture("service-hubble-policy-drop.json"))

    assert report.outcome is Outcome.FINDING
    assert any(
        "all Service-selected Pods Ready=False" in item
        for item in report.derived_findings
    )
    assert any("policy-related" in item for item in report.confirmed_causes)
    resources = {item.resource for item in report.observed_evidence}
    assert "Service/shop/checkout (uid=svc-1)" in resources
    assert "PodList/shop@201" in resources
    assert "HubbleFlowWindow/2026-10-26T11:59:00Z..2026-10-26T12:00:00Z" in resources


def test_ready_endpoint_and_relevant_drop_are_both_reported() -> None:
    report = diagnose(fixture("service-ready-endpoint-hubble-drop.json"))

    assert report.outcome is Outcome.NO_FINDING
    assert report.summary.endswith("correlated Hubble drops were observed")
    assert any("reports a ready endpoint" in item for item in report.derived_findings)
    assert any("matching dropped flows" in item for item in report.derived_findings)
    assert any("does not establish" in item for item in report.limitations)


def test_endpoint_slice_ip_can_correlate_when_hubble_pod_name_is_missing() -> None:
    value = fixture("service-hubble-policy-drop.json")
    value["flows"][0]["destination"]["namespace"] = None
    value["flows"][0]["destination"]["pod"] = None

    report = diagnose(value)

    hubble = next(item for item in report.observed_evidence if item.source == "hubble")
    assert any("1 EndpointSlice-IP matches" in item for item in hubble.transformations)
    assert any("policy-related" in item for item in report.confirmed_causes)


def test_conflicting_pod_identity_and_endpoint_ip_are_not_correlated() -> None:
    value = fixture("service-hubble-policy-drop.json")
    value["flows"][0]["destination"]["namespace"] = "other"

    report = diagnose(value)

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any("conflicting Pod-identity" in item for item in report.limitations)


def test_namespace_and_selector_mismatch_do_not_correlate_flow() -> None:
    value = fixture("service-hubble-policy-drop.json")
    value["podList"]["items"][0]["metadata"]["labels"]["app"] = "other"
    value["flows"][0]["destination"].update(
        {"namespace": "other", "pod": "checkout-abc12", "ip": "10.244.9.9"}
    )

    report = diagnose(value)

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any("did not match" in item for item in report.limitations)


def test_network_policy_restriction_without_flow_drop_remains_possible() -> None:
    value = fixture("service-networkpolicy-ingress-default-deny.json")
    add_flow_collection(value, [])

    report = diagnose(value)

    assert any(
        "did not establish a corresponding policy drop" in item
        for item in report.possible_causes
    )
    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)


def test_explicit_policy_drop_and_policy_spec_are_correlated_but_not_conflated() -> (
    None
):
    value = fixture("service-networkpolicy-ingress-default-deny.json")
    add_flow_collection(value, [relevant_flow()])

    report = diagnose(value)

    assert any(
        "independently reports explicit policy-denial" in item
        for item in report.derived_findings
    )
    assert any("does not identify which policy" in item for item in report.limitations)


def test_policy_allow_and_explicit_hubble_denial_are_reported_as_disagreement() -> None:
    value = fixture("service-networkpolicy-ingress-default-deny.json")
    value["networkPolicyList"]["items"][0]["spec"]["ingress"] = [
        {"from": [], "ports": []}
    ]
    add_flow_collection(value, [relevant_flow()])

    report = diagnose(value)

    assert any(
        "allows the described traffic" in item and "Hubble reports" in item
        for item in report.derived_findings
    )
    assert any("another policy source" in item for item in report.limitations)


def test_forwarded_flow_does_not_erase_no_ready_endpoint_finding() -> None:
    value = fixture("service-hubble-policy-drop.json")
    value["flows"][0].update(
        {"verdict": "FORWARDED", "dropReason": None, "policyRelated": False}
    )

    report = diagnose(value)

    assert report.outcome is Outcome.FINDING
    assert any("forwarded traffic" in item for item in report.derived_findings)
    assert any("different packets or moments" in item for item in report.limitations)
    assert any("application-level success" in item for item in report.limitations)


def test_ready_endpoint_and_all_matching_pods_unready_are_qualified() -> None:
    value = fixture("service-matching-pods-not-ready.json")
    value["endpointSliceList"]["items"][0]["endpoints"][0]["conditions"]["ready"] = True

    report = diagnose(value)

    assert report.outcome is Outcome.NO_FINDING
    assert any("while PodList" in item for item in report.derived_findings)
    assert any("reads are not atomic" in item for item in report.limitations)


def test_incomplete_hubble_collection_cannot_confirm_policy_drop() -> None:
    value = fixture("service-hubble-policy-drop.json")
    add_flow_collection(value, value["flows"], status="incomplete")

    report = diagnose(value)

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any(issue.code == "timeout" for issue in report.collection_issues)
    assert any("collection status is incomplete" in item for item in report.limitations)


def test_missing_service_endpoint_identifiers_are_insufficient() -> None:
    value = fixture("service-hubble-policy-drop.json")
    value["flows"][0]["destination"] = {
        "namespace": None,
        "pod": None,
        "identity": 3,
        "ip": None,
    }

    report = diagnose(value)

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any("did not match" in item for item in report.limitations)


def test_out_of_window_flow_is_excluded_as_stale() -> None:
    value = fixture("service-hubble-policy-drop.json")
    value["flows"][0]["timestamp"] = "2026-10-26T11:58:59Z"

    report = diagnose(value)

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any(
        "outside the declared Hubble window" in item for item in report.limitations
    )


def test_fractional_timestamp_after_window_is_excluded() -> None:
    value = fixture("service-hubble-policy-drop.json")
    value["flows"][0]["timestamp"] = "2026-10-26T12:00:00.500000Z"

    report = diagnose(value)

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any(
        "outside the declared Hubble window" in item for item in report.limitations
    )


def test_non_overlapping_flow_window_is_not_correlated() -> None:
    value = fixture("service-hubble-policy-drop.json")
    value["collection"]["hubbleFlowCollection"]["window"] = {
        "start": "2026-10-26T10:59:00Z",
        "end": "2026-10-26T11:00:00Z",
    }
    value["flows"][0]["timestamp"] = "2026-10-26T10:59:45Z"

    report = diagnose(value)

    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any("does not overlap" in item for item in report.derived_findings)
    assert any("stale" in item for item in report.limitations)


def test_exact_duplicate_flow_does_not_change_report() -> None:
    value = fixture("service-hubble-policy-drop.json")
    duplicate = deepcopy(value)
    duplicate["flows"].append(deepcopy(duplicate["flows"][0]))

    assert report_payload(diagnose(value)) == report_payload(diagnose(duplicate))


def test_report_schema_remains_v2() -> None:
    payload = report_payload(diagnose(fixture("service-hubble-policy-drop.json")))

    assert payload["schemaVersion"] == "kubetrace.report/v2"
