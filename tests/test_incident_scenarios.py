from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kubetrace.cli import main

FIXTURES = Path(__file__).parents[1] / "fixtures"
RULE_ID = "SERVICE_NO_READY_ENDPOINTS"


def run_scenario(name: str, capsys: Any) -> tuple[dict[str, Any], str]:
    """Run one checked-in incident through the production fixture CLI."""

    exit_status = main(["fixture", str(FIXTURES / name)])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_status == 0
    assert payload["schemaVersion"] == "kubetrace.report/v2"
    assert payload["ruleId"] == RULE_ID
    assert payload["explanation"] is not None
    assert payload["explanation"]["supportingEvidence"]
    assert payload["investigationGuidance"]
    assert "NEXT:" in captured.err
    return payload, captured.err


def evidence_resources(payload: dict[str, Any]) -> set[str]:
    return {item["resource"] for item in payload["observedEvidence"]}


def test_scenario_a_service_has_no_ready_endpoints(capsys: Any) -> None:
    payload, terminal = run_scenario("service-no-ready-endpoints.json", capsys)

    assert payload["outcome"] == "finding"
    assert any("zero explicitly ready" in item for item in payload["derivedFindings"])
    assert payload["confirmedCauses"] == []
    assert any(
        "does not independently confirm" in item for item in payload["limitations"]
    )
    assert any(
        "zero explicitly ready" in item
        for item in payload["explanation"]["establishes"]
    )
    assert any(
        item.startswith("EndpointSliceList/") for item in evidence_resources(payload)
    )
    assert "Inspect Pods selected" in terminal


def test_scenario_b_matching_pods_are_explicitly_unready(capsys: Any) -> None:
    payload, terminal = run_scenario("service-matching-pods-not-ready.json", capsys)

    assert payload["outcome"] == "finding"
    assert any(
        "explicitly report Ready=False" in item for item in payload["derivedFindings"]
    )
    assert any("Ready=False" in item for item in payload["confirmedCauses"])
    assert any(
        "not why the Pods are unready" in item for item in payload["limitations"]
    )
    assert any(item.startswith("PodList/") for item in evidence_resources(payload))
    assert "readiness probes" in terminal


def test_scenario_c_selector_matches_no_observed_pods(capsys: Any) -> None:
    payload, terminal = run_scenario("service-selector-matches-no-pods.json", capsys)

    assert payload["outcome"] == "finding"
    assert any("selector matches none" in item for item in payload["derivedFindings"])
    assert payload["confirmedCauses"] == []
    assert any("selector may not match" in item for item in payload["possibleCauses"])
    assert any(
        "does not establish which Pods" in item for item in payload["limitations"]
    )
    assert any(
        "not confirmed causes" in item
        for item in payload["explanation"]["doesNotEstablish"]
    )
    assert "Compare the selector" in terminal


def test_scenario_d_policy_configuration_is_only_a_possible_restriction(
    capsys: Any,
) -> None:
    payload, terminal = run_scenario(
        "service-networkpolicy-ingress-default-deny.json", capsys
    )

    assert payload["outcome"] == "finding"
    assert any("does not allow" in item for item in payload["derivedFindings"])
    assert any("may restrict" in item for item in payload["possibleCauses"])
    assert not any("NetworkPolicy" in item for item in payload["confirmedCauses"])
    assert any(
        "do not prove" in item or "not proof" in item for item in payload["limitations"]
    )
    assert any(
        item.startswith("NetworkPolicyList/") for item in evidence_resources(payload)
    )
    assert "Inspect the applicable NetworkPolicy" in terminal


def test_scenario_e_explicit_hubble_policy_denial_is_correlated(capsys: Any) -> None:
    payload, terminal = run_scenario("incident-explicit-policy-denial.json", capsys)

    assert payload["outcome"] == "finding"
    assert any(
        "explicit policy-denial drops" in item for item in payload["derivedFindings"]
    )
    assert any(
        "Hubble explicitly classified" in item for item in payload["confirmedCauses"]
    )
    assert any(
        "does not identify which policy" in item for item in payload["limitations"]
    )
    assert {item["source"] for item in payload["observedEvidence"]} == {
        "fixture",
        "hubble",
    }
    resources = evidence_resources(payload)
    assert any(item.startswith("NetworkPolicyList/") for item in resources)
    assert any(item.startswith("HubbleFlowWindow/") for item in resources)
    assert any(
        "Cilium policy enforcement" in item for item in payload["investigationGuidance"]
    )
    assert "Inspect the applicable NetworkPolicy" in terminal


def test_scenario_f_generic_hubble_drop_is_not_attributed_to_policy(
    capsys: Any,
) -> None:
    payload, terminal = run_scenario("incident-hubble-unattributed-drop.json", capsys)

    assert payload["outcome"] == "no_finding"
    assert any("matching dropped flows" in item for item in payload["derivedFindings"])
    assert payload["confirmedCauses"] == []
    assert not any("NetworkPolicy" in item for item in payload["possibleCauses"])
    assert any(
        "not attributed to NetworkPolicy" in item for item in payload["limitations"]
    )
    assert any(
        item.startswith("HubbleFlowWindow/") for item in evidence_resources(payload)
    )
    assert "do not attribute generic drops to policy" in terminal


def test_scenario_g_incomplete_and_unidentified_evidence_is_inconclusive(
    capsys: Any,
) -> None:
    payload, terminal = run_scenario("incident-incomplete-evidence.json", capsys)

    assert payload["outcome"] == "inconclusive"
    assert payload["confirmedCauses"] == []
    assert {item["code"] for item in payload["collectionIssues"]} == {
        "forbidden",
        "timeout",
    }
    assert any("missing or unknown" in item for item in payload["limitations"])
    assert any("did not match" in item for item in payload["limitations"])
    assert any(
        "list_namespaced_pod" in item
        for item in payload["explanation"]["missingEvidence"]
    )
    assert any(
        "observe_flows" in item for item in payload["explanation"]["missingEvidence"]
    )
    assert not any("Hubble explicitly" in item for item in payload["confirmedCauses"])
    assert "Resolve the reported missing or inconsistent evidence" in terminal


def test_scenario_h_forwarded_flow_does_not_erase_independent_finding(
    capsys: Any,
) -> None:
    payload, terminal = run_scenario(
        "incident-forwarded-with-unready-endpoints.json", capsys
    )

    assert payload["outcome"] == "finding"
    assert any("zero explicitly ready" in item for item in payload["derivedFindings"])
    assert any(
        "matching forwarded flows" in item for item in payload["derivedFindings"]
    )
    assert any("Ready=False" in item for item in payload["confirmedCauses"])
    assert not any("packet drops" in item for item in payload["possibleCauses"])
    assert any(
        "does not prove application-level success" in item
        for item in payload["limitations"]
    )
    assert any("neither resolves" in item for item in payload["limitations"])
    assert any(
        item.startswith("HubbleFlowWindow/") for item in evidence_resources(payload)
    )
    assert "Compare the conflicting source" in terminal
