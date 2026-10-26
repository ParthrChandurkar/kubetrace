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
    projected_label_keys: tuple[str, ...] | None


@dataclass(frozen=True)
class LabelSelectorRequirement:
    key: str
    operator: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class LabelSelector:
    match_labels: tuple[tuple[str, str], ...]
    match_expressions: tuple[LabelSelectorRequirement, ...]


@dataclass(frozen=True)
class NetworkPolicyPort:
    protocol: str
    port: int | str | None
    end_port: int | None


@dataclass(frozen=True)
class IPBlock:
    cidr: str
    exceptions: tuple[str, ...]


@dataclass(frozen=True)
class NetworkPolicyPeer:
    pod_selector: LabelSelector | None
    namespace_selector: LabelSelector | None
    ip_block: IPBlock | None


@dataclass(frozen=True)
class NetworkPolicyRule:
    peers: tuple[NetworkPolicyPeer, ...]
    ports: tuple[NetworkPolicyPort, ...]


@dataclass(frozen=True)
class NetworkPolicy:
    namespace: str
    name: str
    uid: str
    pod_selector: LabelSelector
    policy_types: tuple[str, ...]
    ingress: tuple[NetworkPolicyRule, ...]
    egress: tuple[NetworkPolicyRule, ...]

    @property
    def identity(self) -> str:
        return f"{self.namespace}/{self.name}"


@dataclass(frozen=True)
class NetworkPolicyListRequest:
    namespace: str | None


@dataclass(frozen=True)
class NetworkPolicyEvidence:
    collection_status: str
    collection_issues: tuple[CollectionIssue, ...]
    request: NetworkPolicyListRequest | None
    policies: tuple[NetworkPolicy, ...] | None
    resource_version: str | None
    continue_token: str | None
    completeness_issues: tuple[str, ...]


@dataclass(frozen=True)
class TrafficPeer:
    namespace: str | None
    namespace_labels: tuple[tuple[str, str], ...] | None
    pod_labels: tuple[tuple[str, str], ...] | None
    ip: str | None


@dataclass(frozen=True)
class TrafficContext:
    direction: str
    protocol: str
    port: int
    peer: TrafficPeer


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
    network_policy_evidence: NetworkPolicyEvidence | None
    traffic: TrafficContext | None


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
