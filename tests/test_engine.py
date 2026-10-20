from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from kubetrace.engine import (
    MAX_ENDPOINT_SLICES,
    MAX_ENDPOINTS,
    MAX_FIXTURE_BYTES,
    MAX_VALIDATION_ERRORS,
    EvidenceValidationError,
    FixtureCollector,
    normalize,
    run_diagnostic,
)
from kubetrace.models import DiagnosticReport, Outcome
from kubetrace.reporting import report_payload, to_json, validation_error_payload

FIXTURES = Path(__file__).parents[1] / "fixtures"


class StaticCollector:
    def __init__(self, evidence: dict[str, Any]) -> None:
        self.evidence = evidence

    def collect(self) -> dict[str, Any]:
        return self.evidence


def fixture_evidence(*, ready_values: list[bool | None]) -> dict[str, Any]:
    endpoints: list[dict[str, Any]] = []
    for index, ready in enumerate(ready_values, start=10):
        endpoint: dict[str, Any] = {"addresses": [f"10.244.0.{index}"]}
        if ready is not None:
            endpoint["conditions"] = {"ready": ready}
        endpoints.append(endpoint)

    return {
        "schemaVersion": "kubetrace.evidence/v1",
        "collection": {
            "source": "fixture",
            "collectedAt": "2026-10-16T17:30:00+05:30",
            "status": "complete",
            "scope": {"namespace": "shop", "serviceName": "checkout"},
            "endpointSliceListRequest": {
                "namespace": "shop",
                "labelSelector": "kubernetes.io/service-name=checkout",
            },
        },
        "service": {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "namespace": "shop",
                "name": "checkout",
                "uid": "service-checkout",
            },
            "spec": {"type": "ClusterIP", "selector": {"app": "checkout"}},
        },
        "endpointSliceList": {
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSliceList",
            "metadata": {"resourceVersion": "100", "continue": ""},
            "items": [endpoint_slice("checkout-a", endpoints)],
        },
    }


def endpoint_slice(
    name: str,
    endpoints: list[dict[str, Any]],
    *,
    namespace: str = "shop",
    service_name: str | None = "checkout",
    address_type: str = "IPv4",
) -> dict[str, Any]:
    labels = (
        {} if service_name is None else {"kubernetes.io/service-name": service_name}
    )
    return {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "addressType": address_type,
        "metadata": {
            "namespace": namespace,
            "name": name,
            "labels": labels,
        },
        "endpoints": endpoints,
    }


def diagnose(evidence: dict[str, Any]) -> DiagnosticReport:
    return run_diagnostic(StaticCollector(evidence))


def test_empty_endpoint_slice_list_with_valid_provenance_is_finding() -> None:
    evidence = fixture_evidence(ready_values=[])
    evidence["endpointSliceList"]["items"] = []

    report = diagnose(evidence)

    assert report.outcome is Outcome.FINDING
    assert report.derived_findings == (
        "The complete associated EndpointSlice snapshot contains zero "
        "explicitly ready logical endpoints.",
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            "missing",
            "EndpointSlice list-request provenance is missing",
        ),
        (
            "namespace",
            "EndpointSlice list-request namespace does not match the Service",
        ),
        (
            "selector",
            "EndpointSlice list-request label selector does not exactly match "
            "the Service",
        ),
    ],
)
def test_missing_or_mismatched_request_provenance_is_inconclusive(
    mutation: str, expected: str
) -> None:
    evidence = fixture_evidence(ready_values=[])
    request = evidence["collection"]["endpointSliceListRequest"]
    if mutation == "missing":
        del evidence["collection"]["endpointSliceListRequest"]
    elif mutation == "namespace":
        request["namespace"] = "other"
    else:
        request["labelSelector"] = "kubernetes.io/service-name=other"

    report = diagnose(evidence)

    assert report.outcome is Outcome.INCONCLUSIVE
    assert expected in report.limitations
    assert report.derived_findings == ()


@pytest.mark.parametrize("continuation", [None, ""])
def test_missing_or_empty_continuation_is_complete(
    continuation: str | None,
) -> None:
    evidence = fixture_evidence(ready_values=[])
    if continuation is None:
        del evidence["endpointSliceList"]["metadata"]["continue"]
    else:
        evidence["endpointSliceList"]["metadata"]["continue"] = continuation

    assert diagnose(evidence).outcome is Outcome.FINDING


def test_nonempty_continuation_is_inconclusive() -> None:
    evidence = fixture_evidence(ready_values=[])
    evidence["endpointSliceList"]["metadata"]["continue"] = "next-page"

    report = diagnose(evidence)

    assert report.outcome is Outcome.INCONCLUSIVE
    assert report.limitations == (
        "EndpointSlice list pagination is incomplete (continue token present)",
    )


@pytest.mark.parametrize("resource_version", [None, ""])
def test_missing_or_empty_resource_version_is_inconclusive(
    resource_version: str | None,
) -> None:
    evidence = fixture_evidence(ready_values=[])
    if resource_version is None:
        del evidence["endpointSliceList"]["metadata"]["resourceVersion"]
    else:
        evidence["endpointSliceList"]["metadata"]["resourceVersion"] = ""

    report = diagnose(evidence)

    assert report.outcome is Outcome.INCONCLUSIVE
    assert report.limitations == ("EndpointSlice list has no resourceVersion snapshot",)


def test_duplicate_endpoint_slice_identity_is_inconclusive() -> None:
    evidence = fixture_evidence(ready_values=[False])
    duplicate = deepcopy(evidence["endpointSliceList"]["items"][0])
    evidence["endpointSliceList"]["items"].append(duplicate)

    report = diagnose(evidence)

    assert report.outcome is Outcome.INCONCLUSIVE
    assert report.limitations == ("EndpointSlice identities are duplicated",)


def test_duplicate_logical_endpoint_is_deduplicated() -> None:
    evidence = fixture_evidence(ready_values=[False])
    duplicate = endpoint_slice(
        "checkout-b",
        [{"addresses": ["10.244.0.10"], "conditions": {"ready": False}}],
    )
    evidence["endpointSliceList"]["items"].append(duplicate)

    report = diagnose(evidence)

    assert report.outcome is Outcome.FINDING
    assert "2 endpoint records, and 1 unique logical endpoints" in (
        report.observed_evidence[1].statement
    )


def test_conflicting_duplicate_endpoint_readiness_is_inconclusive() -> None:
    evidence = fixture_evidence(ready_values=[False])
    conflicting = endpoint_slice(
        "checkout-b",
        [{"addresses": ["10.244.0.10"], "conditions": {"ready": True}}],
    )
    evidence["endpointSliceList"]["items"].append(conflicting)

    report = diagnose(evidence)

    assert report.outcome is Outcome.INCONCLUSIVE
    assert report.limitations == (
        "Conflicting readiness was reported for logical endpoints: " "IPv4:10.244.0.10",
    )


@pytest.mark.parametrize("address_type", ["FQDN", "", "ipv4"])
def test_invalid_address_type_is_validation_error(address_type: str) -> None:
    evidence = fixture_evidence(ready_values=[False])
    evidence["endpointSliceList"]["items"][0]["addressType"] = address_type

    with pytest.raises(EvidenceValidationError, match="addressType"):
        normalize(evidence)


@pytest.mark.parametrize(
    ("address_type", "address"),
    [("IPv4", "not-an-ip"), ("IPv4", "2001:db8::1"), ("IPv6", "10.0.0.1")],
)
def test_malformed_or_mismatched_address_is_validation_error(
    address_type: str, address: str
) -> None:
    evidence = fixture_evidence(ready_values=[False])
    endpoint_slice_value = evidence["endpointSliceList"]["items"][0]
    endpoint_slice_value["addressType"] = address_type
    endpoint_slice_value["endpoints"][0]["addresses"] = [address]

    with pytest.raises(EvidenceValidationError, match="address"):
        normalize(evidence)


def test_ipv6_is_canonicalized_for_logical_identity() -> None:
    evidence = fixture_evidence(ready_values=[False])
    endpoint_slice_value = evidence["endpointSliceList"]["items"][0]
    endpoint_slice_value["addressType"] = "IPv6"
    endpoint_slice_value["endpoints"][0]["addresses"] = ["2001:0db8::1"]
    duplicate = endpoint_slice(
        "checkout-b",
        [{"addresses": ["2001:db8::1"], "conditions": {"ready": False}}],
        address_type="IPv6",
    )
    evidence["endpointSliceList"]["items"].append(duplicate)

    report = diagnose(evidence)

    assert report.outcome is Outcome.FINDING
    assert "1 unique logical endpoints" in report.observed_evidence[1].statement


def test_invalid_service_type_is_validation_error() -> None:
    evidence = fixture_evidence(ready_values=[])
    evidence["service"]["spec"]["type"] = "BogusType"

    with pytest.raises(EvidenceValidationError, match="service.spec.type"):
        normalize(evidence)


@pytest.mark.parametrize(
    "external_name", [None, "Bad Name", "UPPER.example", "bad..example"]
)
def test_invalid_external_name_is_validation_error(
    external_name: str | None,
) -> None:
    evidence = fixture_evidence(ready_values=[])
    evidence["service"]["spec"] = {"type": "ExternalName"}
    if external_name is not None:
        evidence["service"]["spec"]["externalName"] = external_name

    with pytest.raises(EvidenceValidationError, match="externalName"):
        normalize(evidence)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "Bad_Name"),
        ("name", "bad\nname"),
        ("name", "1checkout"),
        ("namespace", "bad.namespace"),
    ],
)
def test_invalid_service_identity_is_validation_error(field: str, value: str) -> None:
    evidence = fixture_evidence(ready_values=[])
    evidence["service"]["metadata"][field] = value

    with pytest.raises(EvidenceValidationError, match=f"service.metadata.{field}"):
        normalize(evidence)


def selectorless_evidence(ready_values: list[bool | None]) -> dict[str, Any]:
    evidence = fixture_evidence(ready_values=ready_values)
    del evidence["service"]["spec"]["selector"]
    return evidence


def test_selectorless_service_with_zero_slices_has_precise_cause() -> None:
    evidence = selectorless_evidence([])
    evidence["endpointSliceList"]["items"] = []

    report = diagnose(evidence)

    assert report.outcome is Outcome.FINDING
    assert report.possible_causes == (
        "EndpointSlices may not have been configured for the selectorless Service.",
    )


def test_selectorless_service_with_empty_slice_has_precise_cause() -> None:
    report = diagnose(selectorless_evidence([]))

    assert report.outcome is Outcome.FINDING
    assert report.possible_causes == (
        "The observed EndpointSlices are configured without endpoints.",
    )


@pytest.mark.parametrize(
    ("ready", "outcome"),
    [(True, Outcome.NO_FINDING), (None, Outcome.INCONCLUSIVE)],
)
def test_selectorless_ready_and_unknown_outcomes(
    ready: bool | None, outcome: Outcome
) -> None:
    assert diagnose(selectorless_evidence([ready])).outcome is outcome


@pytest.mark.parametrize(
    ("readiness", "cause"),
    [
        ([False], "The manually managed endpoint is explicitly unready."),
        (
            [False, False],
            "All 2 manually managed endpoints are explicitly unready.",
        ),
    ],
)
def test_selectorless_unready_endpoints_have_precise_cause(
    readiness: list[bool], cause: str
) -> None:
    report = diagnose(selectorless_evidence(readiness))

    assert report.outcome is Outcome.FINDING
    assert report.possible_causes == (cause,)


def test_fixture_size_limit(tmp_path: Path) -> None:
    fixture = tmp_path / "large.json"
    fixture.write_bytes(b" " * (MAX_FIXTURE_BYTES + 1))

    with pytest.raises(EvidenceValidationError, match="byte limit"):
        FixtureCollector(fixture).collect()


def test_endpoint_slice_count_limit() -> None:
    evidence = fixture_evidence(ready_values=[])
    item = evidence["endpointSliceList"]["items"][0]
    evidence["endpointSliceList"]["items"] = [item] * (MAX_ENDPOINT_SLICES + 1)

    with pytest.raises(EvidenceValidationError, match="slice limit"):
        normalize(evidence)


def test_endpoint_count_limit() -> None:
    evidence = fixture_evidence(ready_values=[])
    endpoint = {"addresses": ["10.0.0.1"], "conditions": {"ready": False}}
    evidence["endpointSliceList"]["items"][0]["endpoints"] = [endpoint] * (
        MAX_ENDPOINTS + 1
    )

    with pytest.raises(EvidenceValidationError, match="endpoint limit"):
        normalize(evidence)


def test_validation_error_limit() -> None:
    evidence = fixture_evidence(ready_values=[])
    evidence["endpointSliceList"]["items"][0]["endpoints"] = [
        {} for _ in range(MAX_VALIDATION_ERRORS + 1)
    ]

    with pytest.raises(EvidenceValidationError) as raised:
        normalize(evidence)

    assert raised.value.errors[-1] == (
        f"validation stopped after {MAX_VALIDATION_ERRORS} errors"
    )
    assert len(raised.value.errors) == MAX_VALIDATION_ERRORS + 1


@pytest.mark.parametrize("mismatch", ["scope-namespace", "slice-namespace"])
def test_namespace_mismatch_is_inconclusive(mismatch: str) -> None:
    evidence = fixture_evidence(ready_values=[])
    if mismatch == "scope-namespace":
        evidence["collection"]["scope"]["namespace"] = "other"
    else:
        evidence["endpointSliceList"]["items"][0]["metadata"]["namespace"] = "other"

    assert diagnose(evidence).outcome is Outcome.INCONCLUSIVE


def test_missing_association_label_is_inconclusive() -> None:
    evidence = fixture_evidence(ready_values=[])
    evidence["endpointSliceList"]["items"][0]["metadata"]["labels"] = {}

    assert diagnose(evidence).outcome is Outcome.INCONCLUSIVE


@pytest.mark.parametrize("include_valid_slice", [False, True])
def test_mismatched_ready_slice_cannot_produce_no_finding(
    include_valid_slice: bool,
) -> None:
    evidence = fixture_evidence(ready_values=[])
    mismatched = endpoint_slice(
        "other-a",
        [{"addresses": ["10.244.0.99"], "conditions": {"ready": True}}],
        service_name="other",
    )
    evidence["endpointSliceList"]["items"] = (
        [evidence["endpointSliceList"]["items"][0], mismatched]
        if include_valid_slice
        else [mismatched]
    )

    report = diagnose(evidence)

    assert report.outcome is Outcome.INCONCLUSIVE
    assert report.derived_findings == ()


@pytest.mark.parametrize("timestamp", ["not-a-time", "2026-10-16T12:00:00"])
def test_invalid_timestamp_is_validation_error(timestamp: str) -> None:
    evidence = fixture_evidence(ready_values=[])
    evidence["collection"]["collectedAt"] = timestamp

    with pytest.raises(EvidenceValidationError, match="collectedAt"):
        normalize(evidence)


def test_timestamp_is_normalized_to_utc_and_source_is_preserved() -> None:
    bundle = normalize(fixture_evidence(ready_values=[]))

    assert bundle.source_collected_at == "2026-10-16T17:30:00+05:30"
    assert bundle.collected_at == "2026-10-16T12:00:00Z"


def test_invalid_readiness_type_is_validation_error() -> None:
    evidence = fixture_evidence(ready_values=[False])
    endpoint = evidence["endpointSliceList"]["items"][0]["endpoints"][0]
    endpoint["conditions"]["ready"] = "false"

    with pytest.raises(EvidenceValidationError, match="conditions.ready"):
        normalize(evidence)


@pytest.mark.parametrize(
    ("filename", "outcome"),
    [
        ("service-no-ready-endpoints.json", Outcome.FINDING),
        ("service-with-ready-endpoint.json", Outcome.NO_FINDING),
    ],
)
def test_checked_in_fixtures_use_normal_pipeline(
    filename: str, outcome: Outcome
) -> None:
    assert run_diagnostic(FixtureCollector(FIXTURES / filename)).outcome is outcome


def test_reordered_slices_and_endpoints_have_deterministic_output() -> None:
    evidence = fixture_evidence(ready_values=[False, False])
    second = endpoint_slice(
        "checkout-b",
        [{"addresses": ["10.244.0.30"], "conditions": {"ready": False}}],
    )
    evidence["endpointSliceList"]["items"].append(second)
    reordered = deepcopy(evidence)
    reordered["endpointSliceList"]["items"].reverse()
    for item in reordered["endpointSliceList"]["items"]:
        item["endpoints"].reverse()

    first = to_json(report_payload(diagnose(evidence)))
    second_output = to_json(report_payload(diagnose(reordered)))

    assert first == second_output


def test_normal_report_has_exact_shape_and_cause_text() -> None:
    payload = report_payload(diagnose(fixture_evidence(ready_values=[False])))

    assert set(payload) == {
        "schemaVersion",
        "ruleId",
        "outcome",
        "summary",
        "target",
        "service",
        "collectionIssues",
        "observedEvidence",
        "derivedFindings",
        "possibleCauses",
        "confirmedCauses",
        "limitations",
        "errors",
    }
    assert payload["possibleCauses"] == [
        "No matching Pods may exist.",
        "The Service selector may not match the intended Pods.",
        "Matching Pods may be failing readiness checks.",
        "EndpointSlice controller data may not have converged.",
    ]
    assert payload["confirmedCauses"] == []
    assert payload["collectionIssues"] == []
    assert payload["errors"] == []
    assert payload["target"] == {
        "namespace": "shop",
        "serviceName": "checkout",
    }
    assert payload["observedEvidence"][0]["sourceCollectedAt"] == (
        "2026-10-16T17:30:00+05:30"
    )
    assert payload["observedEvidence"][0]["collectedAt"] == "2026-10-16T12:00:00Z"
    assert payload["observedEvidence"][0]["transformations"] == [
        "validated against kubetrace.evidence/v1",
        "normalized to KubeTrace domain models",
    ]


def test_validation_error_report_has_exact_shape() -> None:
    payload = validation_error_payload(("bad input",))

    assert set(payload) == {
        "schemaVersion",
        "ruleId",
        "outcome",
        "summary",
        "target",
        "service",
        "collectionIssues",
        "errors",
        "observedEvidence",
        "derivedFindings",
        "possibleCauses",
        "confirmedCauses",
        "limitations",
    }
    assert payload["service"] is None
    assert payload["target"] is None
    assert payload["collectionIssues"] == []
    assert payload["errors"] == ["bad input"]
    assert payload["outcome"] == "validation_error"


def test_json_serialization_is_stable_for_identical_payloads() -> None:
    payload = report_payload(diagnose(fixture_evidence(ready_values=[False])))

    assert to_json(deepcopy(payload)) == to_json(payload)
    assert json.loads(to_json(payload)) == payload
