"""Typed domain models for the diagnostic pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

EVIDENCE_SCHEMA_VERSION = "kubetrace.evidence/v1"
REPORT_SCHEMA_VERSION = "kubetrace.report/v2"
RULE_ID = "SERVICE_NO_READY_ENDPOINTS"


class Outcome(StrEnum):
    """Stable diagnostic outcomes emitted by the engine."""

    FINDING = "finding"
    NO_FINDING = "no_finding"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    VALIDATION_ERROR = "validation_error"


@dataclass(frozen=True)
class CollectionScope:
    namespace: str
    service_name: str


@dataclass(frozen=True)
class EndpointSliceRequest:
    namespace: str | None
    label_selector: str | None


@dataclass(frozen=True)
class PodListRequest:
    namespace: str | None
    label_selector: str | None


@dataclass(frozen=True)
class CollectionIssue:
    operation: str
    code: str
    message: str
    status: int | None


@dataclass(frozen=True)
class Service:
    namespace: str
    name: str
    uid: str
    service_type: str
    selector: tuple[tuple[str, str], ...] | None
    external_name: str | None

    @property
    def identity(self) -> str:
        return f"{self.namespace}/{self.name}"


@dataclass(frozen=True)
class Endpoint:
    address_type: str
    address: str
    ready: bool | None

    @property
    def identity(self) -> tuple[str, str]:
        return (self.address_type, self.address)


@dataclass(frozen=True)
class EndpointSlice:
    namespace: str
    name: str
    service_name: str | None
    address_type: str
    endpoints: tuple[Endpoint, ...]

    @property
    def identity(self) -> str:
        return f"{self.namespace}/{self.name}"


@dataclass(frozen=True)
class Pod:
    namespace: str
    name: str
    uid: str
    labels: tuple[tuple[str, str], ...]
    ready: bool | None

    @property
    def identity(self) -> str:
        return f"{self.namespace}/{self.name}"


@dataclass(frozen=True)
class PodEvidence:
    collection_status: str
    collection_issues: tuple[CollectionIssue, ...]
    request: PodListRequest | None
    pods: tuple[Pod, ...] | None
    resource_version: str | None
    continue_token: str | None
    completeness_issues: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceBundle:
    source: str
    source_collected_at: str
    collected_at: str
    collection_status: str
    scope: CollectionScope
    collection_issues: tuple[CollectionIssue, ...]
    endpoint_slice_request: EndpointSliceRequest | None
    service: Service | None
    endpoint_slices: tuple[EndpointSlice, ...] | None
    endpoint_slice_resource_version: str | None
    endpoint_slice_continue: str | None
    completeness_issues: tuple[str, ...]
    pod_evidence: PodEvidence | None


@dataclass(frozen=True)
class ObservedEvidence:
    statement: str
    source: str
    source_collected_at: str
    collected_at: str
    resource: str
    transformations: tuple[str, ...]


@dataclass(frozen=True)
class DiagnosticReport:
    rule_id: str
    outcome: Outcome
    summary: str
    target: CollectionScope
    service: Service | None
    collection_issues: tuple[CollectionIssue, ...]
    observed_evidence: tuple[ObservedEvidence, ...]
    derived_findings: tuple[str, ...]
    possible_causes: tuple[str, ...]
    confirmed_causes: tuple[str, ...]
    limitations: tuple[str, ...]
