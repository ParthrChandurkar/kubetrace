from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from kubetrace.engine import run_diagnostic
from kubetrace.models import DiagnosticReport, Outcome
from kubetrace.reporting import report_payload, validation_error_payload

FIXTURES = Path(__file__).parents[1] / "fixtures"


class StaticCollector:
    def __init__(self, evidence: dict[str, Any]) -> None:
        self.evidence = evidence

    def collect(self) -> dict[str, Any]:
        return self.evidence


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def diagnose(evidence: dict[str, Any]) -> DiagnosticReport:
    return run_diagnostic(StaticCollector(evidence))


def test_no_ready_endpoints_explains_evidence_and_next_step() -> None:
    report = diagnose(fixture("service-no-ready-endpoints.json"))
    payload = report_payload(report)

    assert payload["schemaVersion"] == "kubetrace.report/v2"
    explanation = payload["explanation"]
    assert explanation is not None
    assert any("zero explicitly ready" in item for item in explanation["establishes"])
    assert any(
        item["source"] == "fixture" and item["resource"].startswith("Service/")
        for item in explanation["supportingEvidence"]
    )
    assert any(
        "Inspect Pods selected" in item for item in payload["investigationGuidance"]
    )


def test_unready_pods_explain_immediate_condition_not_root_cause() -> None:
    report = diagnose(fixture("service-matching-pods-not-ready.json"))

    assert report.explanation is not None
    assert any("Ready=False" in item for item in report.explanation.establishes)
    assert any(
        "not why the Pods are unready" in item
        for item in report.explanation.does_not_establish
    )
    assert any("readiness probes" in item for item in report.investigation_guidance)


def test_selector_mismatch_remains_a_possible_cause() -> None:
    report = diagnose(fixture("service-selector-matches-no-pods.json"))

    assert report.confirmed_causes == ()
    assert report.possible_causes
    assert report.explanation is not None
    assert any(
        "not confirmed causes" in item for item in report.explanation.does_not_establish
    )
    assert any("Compare the selector" in item for item in report.investigation_guidance)


def test_ready_endpoint_does_not_recommend_endpoint_correction() -> None:
    report = diagnose(fixture("service-with-ready-endpoint.json"))

    assert report.outcome is Outcome.NO_FINDING
    assert report.explanation is not None
    assert any(
        "does not produce a finding" in item for item in report.explanation.establishes
    )
    assert not any("readiness probes" in item for item in report.investigation_guidance)
    assert report.investigation_guidance == (
        "No endpoint-readiness correction is indicated for Service shop/checkout; "
        "continue with the other reported network evidence.",
    )


def test_policy_restriction_guidance_requires_policy_evidence() -> None:
    with_policy = diagnose(fixture("service-networkpolicy-ingress-default-deny.json"))
    without_policy = diagnose(fixture("service-matching-pods-not-ready.json"))

    assert any(
        "applicable NetworkPolicy" in item
        for item in with_policy.investigation_guidance
    )
    assert not any(
        "NetworkPolicy" in item for item in without_policy.investigation_guidance
    )


def test_explicit_hubble_policy_denial_has_provenance_and_bounded_guidance() -> None:
    report = diagnose(fixture("service-hubble-policy-drop.json"))

    assert report.explanation is not None
    assert any(item.source == "hubble" for item in report.observed_evidence)
    assert any(
        "HubbleFlowWindow/" in item.resource for item in report.observed_evidence
    )
    assert any(
        "Cilium policy enforcement" in item for item in report.investigation_guidance
    )
    assert any(
        "does not by itself establish causation" in item
        for item in report.explanation.does_not_establish
    )


def test_incomplete_hubble_evidence_is_missing_and_gets_recollection_guidance() -> None:
    evidence = fixture("service-hubble-policy-drop.json")
    evidence["collection"]["hubbleFlowCollection"]["status"] = "incomplete"
    evidence["collection"]["hubbleFlowCollection"]["issues"] = [
        {
            "operation": "observe_flows",
            "code": "timeout",
            "message": "Hubble observation timed out.",
            "status": None,
        }
    ]
    report = diagnose(evidence)

    assert report.explanation is not None
    assert any("observe_flows" in item for item in report.explanation.missing_evidence)
    assert not any("Hubble explicitly" in item for item in report.confirmed_causes)
    assert any("Hubble CLI or Relay" in item for item in report.investigation_guidance)


def test_incomplete_pod_evidence_gets_only_relevant_collection_guidance() -> None:
    evidence = fixture("service-matching-pods-not-ready.json")
    evidence["collection"]["podListCollection"]["status"] = "incomplete"
    evidence["collection"]["podListCollection"]["issues"] = [
        {
            "operation": "list_namespaced_pod",
            "code": "forbidden",
            "message": "Kubernetes API access was denied.",
            "status": 403,
        }
    ]
    report = diagnose(evidence)

    assert report.confirmed_causes == ()
    assert report.explanation is not None
    assert any(
        "list_namespaced_pod" in item for item in report.explanation.missing_evidence
    )
    assert any("Pod list access" in item for item in report.investigation_guidance)
    assert not any("Hubble" in item for item in report.investigation_guidance)


def test_contradictory_sources_prompt_comparison_not_a_new_cause() -> None:
    evidence = fixture("service-matching-pods-not-ready.json")
    evidence["podList"]["items"][0]["status"]["ready"] = True
    report = diagnose(evidence)

    assert report.confirmed_causes == ()
    assert report.explanation is not None
    assert any("inconsistent" in item for item in report.explanation.does_not_establish)
    assert any(
        "resource versions and timestamps" in item
        for item in report.investigation_guidance
    )


def test_unknown_endpoint_readiness_stays_inconclusive() -> None:
    evidence = fixture("service-no-ready-endpoints.json")
    endpoint = evidence["endpointSliceList"]["items"][0]["endpoints"][0]
    endpoint["conditions"].pop("ready")
    report = diagnose(evidence)

    assert report.outcome is Outcome.INCONCLUSIVE
    assert report.explanation is not None
    assert report.explanation.establishes == ()
    assert any(
        "does not establish whether" in item
        for item in report.explanation.does_not_establish
    )
    assert any("recollect" in item for item in report.investigation_guidance)


def test_external_name_explanation_is_not_applicable_and_dns_focused() -> None:
    evidence = fixture("service-no-ready-endpoints.json")
    evidence["service"]["spec"] = {
        "type": "ExternalName",
        "externalName": "checkout.example.invalid",
    }
    report = diagnose(evidence)

    assert report.outcome is Outcome.NOT_APPLICABLE
    assert report.explanation is not None
    assert any("does not apply" in item for item in report.explanation.establishes)
    assert any("DNS resolution" in item for item in report.investigation_guidance)
    assert not any("readiness probes" in item for item in report.investigation_guidance)


def test_validation_error_explanation_cannot_claim_a_diagnosis() -> None:
    payload = validation_error_payload(("service.metadata.name is required",))

    assert payload["outcome"] == "validation_error"
    assert payload["explanation"]["establishes"] == []
    assert payload["explanation"]["supportingEvidence"] == []
    assert "cannot support" in payload["explanation"]["doesNotEstablish"][0]
    assert payload["investigationGuidance"] == [
        "Correct the reported validation errors and rerun the investigation."
    ]


def test_explanation_is_deterministic_and_does_not_duplicate_raw_objects() -> None:
    evidence = fixture("service-hubble-policy-drop.json")
    first = report_payload(diagnose(evidence))
    second = report_payload(diagnose(deepcopy(evidence)))

    assert first == second
    supporting = first["explanation"]["supportingEvidence"]
    assert all(
        set(item) == {"source", "sourceCollectedAt", "resource", "statement"}
        for item in supporting
    )
