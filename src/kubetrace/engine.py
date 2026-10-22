"""Evidence collection, normalization, and deterministic rule evaluation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Any, Protocol

from kubetrace.models import (
    EVIDENCE_SCHEMA_VERSION,
    RULE_ID,
    CollectionIssue,
    CollectionScope,
    DiagnosticReport,
    Endpoint,
    EndpointSlice,
    EndpointSliceRequest,
    EvidenceBundle,
    ObservedEvidence,
    Outcome,
    Pod,
    PodEvidence,
    PodListRequest,
    Service,
)

SERVICE_NAME_LABEL = "kubernetes.io/service-name"
SUPPORTED_ADDRESS_TYPES = frozenset({"IPv4", "IPv6"})
SUPPORTED_SERVICE_TYPES = frozenset(
    {"ClusterIP", "NodePort", "LoadBalancer", "ExternalName"}
)

MAX_FIXTURE_BYTES = 1_048_576
MAX_ENDPOINT_SLICES = 256
MAX_ENDPOINTS = 10_000
MAX_PODS = 1_000
MAX_VALIDATION_ERRORS = 50

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_SERVICE_NAME = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$")


class EvidenceValidationError(ValueError):
    """Raised when evidence is malformed or structurally invalid."""

    def __init__(self, errors: list[str] | tuple[str, ...]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


class _ValidationErrors(list[str]):
    """Bound validation work and resulting error-report size."""

    def append(self, error: str) -> None:
        if len(self) >= MAX_VALIDATION_ERRORS:
            raise EvidenceValidationError(
                [*self, f"validation stopped after {MAX_VALIDATION_ERRORS} errors"]
            )
        super().append(error)


class EvidenceCollector(Protocol):
    """Contract shared by fixture and future live evidence collectors."""

    def collect(self) -> Mapping[str, Any]:
        """Return an evidence envelope for shared normalization."""


class FixtureCollector:
    """Load a size-bounded evidence envelope from a JSON fixture."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def collect(self) -> Mapping[str, Any]:
        try:
            with self.path.open("rb") as fixture_file:
                encoded = fixture_file.read(MAX_FIXTURE_BYTES + 1)
        except OSError as error:
            raise EvidenceValidationError(
                [f"cannot read fixture {self.path}: {error.strerror or error}"]
            ) from error

        if len(encoded) > MAX_FIXTURE_BYTES:
            raise EvidenceValidationError(
                [f"fixture exceeds the {MAX_FIXTURE_BYTES}-byte limit"]
            )
        try:
            value = json.loads(encoded.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise EvidenceValidationError(["fixture must be valid UTF-8"]) from error
        except json.JSONDecodeError as error:
            raise EvidenceValidationError(
                [f"invalid JSON at line {error.lineno}, column {error.colno}"]
            ) from error

        if not isinstance(value, dict):
            raise EvidenceValidationError(["fixture root must be a JSON object"])
        return value


def _object(value: Any, path: str, errors: list[str]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    errors.append(f"{path} must be an object")
    return {}


def _required_string(value: Any, path: str, errors: list[str]) -> str:
    if isinstance(value, str) and value:
        return value
    errors.append(f"{path} must be a non-empty string")
    return ""


def _optional_string(value: Any, path: str, errors: list[str]) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    errors.append(f"{path} must be a string or null")
    return None


def _safe_string(
    value: Any, path: str, errors: list[str], *, max_length: int = 256
) -> str:
    text = _required_string(value, path, errors)
    if text and (len(text) > max_length or not text.isprintable()):
        errors.append(f"{path} must contain at most {max_length} printable characters")
    return text


def _dns_label(value: Any, path: str, errors: list[str]) -> str:
    text = _required_string(value, path, errors)
    if text and not _DNS_LABEL.fullmatch(text):
        errors.append(f"{path} must be a lowercase DNS label of at most 63 characters")
    return text


def _dns_subdomain(value: Any, path: str, errors: list[str]) -> str:
    text = _required_string(value, path, errors)
    if text and (
        len(text) > 253
        or any(not _DNS_LABEL.fullmatch(label) for label in text.split("."))
    ):
        errors.append(
            f"{path} must be a lowercase DNS subdomain of at most 253 characters"
        )
    return text


def _service_name(value: Any, path: str, errors: list[str]) -> str:
    text = _required_string(value, path, errors)
    if text and not _SERVICE_NAME.fullmatch(text):
        errors.append(
            f"{path} must be a lowercase RFC-1035 label of at most 63 characters"
        )
    return text


def _timestamp(value: Any, path: str, errors: list[str]) -> tuple[str, str]:
    timestamp = _required_string(value, path, errors)
    if not timestamp:
        return timestamp, timestamp
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{path} must be an ISO 8601 timestamp")
        return timestamp, timestamp
    if parsed.tzinfo is None:
        errors.append(f"{path} must include a timezone")
        return timestamp, timestamp
    normalized = parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return timestamp, normalized


def _normalize_collection_issues(
    value: Any, status: str, errors: list[str], *, path: str = "collection.issues"
) -> tuple[CollectionIssue, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        errors.append(f"{path} must be a list")
        return ()
    if len(value) > MAX_VALIDATION_ERRORS:
        errors.append(f"{path} must contain at most {MAX_VALIDATION_ERRORS} items")
        return ()

    issues: list[CollectionIssue] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        issue = _object(item, item_path, errors)
        status_value = issue.get("status")
        if status_value is not None and (
            not isinstance(status_value, int)
            or isinstance(status_value, bool)
            or not 100 <= status_value <= 599
        ):
            errors.append(f"{item_path}.status must be an HTTP status integer or null")
            status_value = None
        issues.append(
            CollectionIssue(
                operation=_safe_string(
                    issue.get("operation"),
                    f"{item_path}.operation",
                    errors,
                    max_length=64,
                ),
                code=_safe_string(
                    issue.get("code"), f"{item_path}.code", errors, max_length=64
                ),
                message=_safe_string(
                    issue.get("message"),
                    f"{item_path}.message",
                    errors,
                    max_length=256,
                ),
                status=status_value,
            )
        )
    if issues and status != "incomplete":
        status_path = path.removesuffix(".issues") + ".status"
        errors.append(f"{status_path} must be 'incomplete' when issues are present")
    return tuple(issues)


def _normalize_service(value: Any, errors: list[str]) -> Service:
    service = _object(value, "service", errors)
    if service.get("apiVersion") != "v1":
        errors.append("service.apiVersion must be 'v1'")
    if service.get("kind") != "Service":
        errors.append("service.kind must be 'Service'")

    metadata = _object(service.get("metadata"), "service.metadata", errors)
    spec = _object(service.get("spec"), "service.spec", errors)
    selector_value = spec.get("selector")
    selector: tuple[tuple[str, str], ...] | None
    if selector_value is None or selector_value == {}:
        selector = None
    elif isinstance(selector_value, dict) and all(
        isinstance(key, str)
        and key
        and key.isprintable()
        and isinstance(item, str)
        and item.isprintable()
        for key, item in selector_value.items()
    ):
        selector = tuple(sorted(selector_value.items()))
    else:
        errors.append("service.spec.selector must map printable strings to strings")
        selector = None

    service_type = _required_string(spec.get("type"), "service.spec.type", errors)
    if service_type and service_type not in SUPPORTED_SERVICE_TYPES:
        errors.append(
            "service.spec.type must be ClusterIP, NodePort, LoadBalancer, or "
            "ExternalName"
        )
    external_name_value = spec.get("externalName")
    external_name: str | None = None
    if service_type == "ExternalName":
        external_name = _dns_subdomain(
            external_name_value, "service.spec.externalName", errors
        )
    elif external_name_value is not None:
        errors.append("service.spec.externalName is only valid for ExternalName")

    return Service(
        namespace=_dns_label(
            metadata.get("namespace"), "service.metadata.namespace", errors
        ),
        name=_service_name(metadata.get("name"), "service.metadata.name", errors),
        uid=_safe_string(metadata.get("uid"), "service.metadata.uid", errors),
        service_type=service_type,
        selector=selector,
        external_name=external_name,
    )


def _canonical_address(
    value: Any, address_type: str, path: str, errors: list[str]
) -> str:
    address = _required_string(value, path, errors)
    if not address:
        return address
    try:
        parsed = ip_address(address)
    except ValueError:
        errors.append(f"{path} must be a valid {address_type} address")
        return address
    expected = IPv4Address if address_type == "IPv4" else IPv6Address
    if not isinstance(parsed, expected):
        errors.append(f"{path} must match addressType {address_type}")
    return str(parsed)


def _normalize_endpoint(
    value: Any,
    address_type: str,
    path: str,
    errors: list[str],
) -> tuple[Endpoint, ...]:
    endpoint = _object(value, path, errors)
    addresses_value = endpoint.get("addresses")
    addresses: tuple[str, ...] = ()
    if isinstance(addresses_value, list) and addresses_value:
        addresses = tuple(
            _canonical_address(
                address, address_type, f"{path}.addresses[{index}]", errors
            )
            for index, address in enumerate(addresses_value)
        )
    else:
        errors.append(f"{path}.addresses must be a non-empty list")

    conditions_value = endpoint.get("conditions")
    if conditions_value is None:
        ready = None
    else:
        conditions = _object(conditions_value, f"{path}.conditions", errors)
        ready_value = conditions.get("ready")
        if ready_value is None or isinstance(ready_value, bool):
            ready = ready_value
        else:
            errors.append(f"{path}.conditions.ready must be true, false, or null")
            ready = None
    return tuple(
        Endpoint(address_type=address_type, address=address, ready=ready)
        for address in addresses
    )


def _normalize_endpoint_slice(
    value: Any, index: int, errors: list[str]
) -> EndpointSlice:
    path = f"endpointSliceList.items[{index}]"
    endpoint_slice = _object(value, path, errors)
    if endpoint_slice.get("apiVersion") != "discovery.k8s.io/v1":
        errors.append(f"{path}.apiVersion must be 'discovery.k8s.io/v1'")
    if endpoint_slice.get("kind") != "EndpointSlice":
        errors.append(f"{path}.kind must be 'EndpointSlice'")

    metadata = _object(endpoint_slice.get("metadata"), f"{path}.metadata", errors)
    labels_value = metadata.get("labels")
    labels = (
        {}
        if labels_value is None
        else _object(labels_value, f"{path}.metadata.labels", errors)
    )
    address_type = _required_string(
        endpoint_slice.get("addressType"), f"{path}.addressType", errors
    )
    if address_type and address_type not in SUPPORTED_ADDRESS_TYPES:
        errors.append(f"{path}.addressType must be IPv4 or IPv6")

    endpoints_value = endpoint_slice.get("endpoints")
    endpoints: tuple[Endpoint, ...] = ()
    if isinstance(endpoints_value, list):
        endpoints = tuple(
            endpoint
            for item_index, item in enumerate(endpoints_value)
            for endpoint in _normalize_endpoint(
                item, address_type, f"{path}.endpoints[{item_index}]", errors
            )
        )
    else:
        errors.append(f"{path}.endpoints must be a list")

    return EndpointSlice(
        namespace=_dns_label(
            metadata.get("namespace"), f"{path}.metadata.namespace", errors
        ),
        name=_dns_subdomain(metadata.get("name"), f"{path}.metadata.name", errors),
        service_name=_optional_string(
            labels.get(SERVICE_NAME_LABEL),
            f"{path}.metadata.labels.{SERVICE_NAME_LABEL}",
            errors,
        ),
        address_type=address_type,
        endpoints=tuple(sorted(endpoints, key=lambda endpoint: endpoint.identity)),
    )


def _normalize_pod(value: Any, index: int, errors: list[str]) -> Pod:
    path = f"podList.items[{index}]"
    pod = _object(value, path, errors)
    if pod.get("apiVersion") != "v1":
        errors.append(f"{path}.apiVersion must be 'v1'")
    if pod.get("kind") != "Pod":
        errors.append(f"{path}.kind must be 'Pod'")

    metadata = _object(pod.get("metadata"), f"{path}.metadata", errors)
    labels_value = metadata.get("labels")
    labels: list[tuple[str, str]] = []
    if not isinstance(labels_value, dict):
        errors.append(f"{path}.metadata.labels must be an object")
    else:
        for key, label_value in labels_value.items():
            if (
                not isinstance(key, str)
                or not key
                or len(key) > 253
                or not key.isprintable()
            ):
                errors.append(
                    f"{path}.metadata.labels keys must be non-empty printable "
                    "strings of at most 253 characters"
                )
                continue
            if (
                not isinstance(label_value, str)
                or len(label_value) > 63
                or not label_value.isprintable()
            ):
                errors.append(
                    f"{path}.metadata.labels.{key} must be a printable string "
                    "of at most 63 characters"
                )
                continue
            labels.append((key, label_value))

    status = _object(pod.get("status"), f"{path}.status", errors)
    ready_value = status.get("ready")
    if ready_value is None or isinstance(ready_value, bool):
        ready = ready_value
    else:
        errors.append(f"{path}.status.ready must be true, false, or null")
        ready = None

    return Pod(
        namespace=_dns_label(
            metadata.get("namespace"), f"{path}.metadata.namespace", errors
        ),
        name=_dns_subdomain(metadata.get("name"), f"{path}.metadata.name", errors),
        uid=_safe_string(metadata.get("uid"), f"{path}.metadata.uid", errors),
        labels=tuple(sorted(labels)),
        ready=ready,
    )


def _validate_collection_limits(items: Any) -> None:
    if not isinstance(items, list):
        return
    if len(items) > MAX_ENDPOINT_SLICES:
        raise EvidenceValidationError(
            [f"EndpointSlice count exceeds the {MAX_ENDPOINT_SLICES}-slice limit"]
        )
    endpoint_count = 0
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("endpoints"), list):
            endpoint_count += len(item["endpoints"])
            if endpoint_count > MAX_ENDPOINTS:
                raise EvidenceValidationError(
                    [f"endpoint count exceeds the {MAX_ENDPOINTS}-endpoint limit"]
                )


def _validate_pod_limit(items: Any) -> None:
    if isinstance(items, list) and len(items) > MAX_PODS:
        raise EvidenceValidationError([f"Pod count exceeds the {MAX_PODS}-Pod limit"])


def _normalize_pod_evidence(
    raw: Mapping[str, Any],
    collection: dict[str, Any],
    scope: CollectionScope,
    errors: list[str],
) -> PodEvidence | None:
    collection_value = collection.get("podListCollection")
    list_value = raw.get("podList")
    if collection_value is None and list_value is None:
        return None

    pod_collection = _object(collection_value, "collection.podListCollection", errors)
    status = _required_string(
        pod_collection.get("status"),
        "collection.podListCollection.status",
        errors,
    )
    if status not in {"complete", "incomplete"}:
        errors.append(
            "collection.podListCollection.status must be 'complete' or 'incomplete'"
        )
    issues = _normalize_collection_issues(
        pod_collection.get("issues"),
        status,
        errors,
        path="collection.podListCollection.issues",
    )

    request_value = pod_collection.get("request")
    request: PodListRequest | None = None
    if request_value is not None:
        request_object = _object(
            request_value, "collection.podListCollection.request", errors
        )
        request = PodListRequest(
            namespace=_optional_string(
                request_object.get("namespace"),
                "collection.podListCollection.request.namespace",
                errors,
            ),
            label_selector=_optional_string(
                request_object.get("labelSelector"),
                "collection.podListCollection.request.labelSelector",
                errors,
            ),
        )

    pods: tuple[Pod, ...] | None = None
    resource_version: str | None = None
    continue_token: str | None = None
    if list_value is not None:
        pod_list = _object(list_value, "podList", errors)
        if pod_list.get("apiVersion") != "v1":
            errors.append("podList.apiVersion must be 'v1'")
        if pod_list.get("kind") != "PodList":
            errors.append("podList.kind must be 'PodList'")
        metadata = _object(pod_list.get("metadata"), "podList.metadata", errors)
        resource_version = _optional_string(
            metadata.get("resourceVersion"),
            "podList.metadata.resourceVersion",
            errors,
        )
        if resource_version is not None and not resource_version.isprintable():
            errors.append("podList.metadata.resourceVersion must be printable")
        continue_token = _optional_string(
            metadata.get("continue"), "podList.metadata.continue", errors
        )
        if continue_token is not None and not continue_token.isprintable():
            errors.append("podList.metadata.continue must be printable")
        items = pod_list.get("items")
        _validate_pod_limit(items)
        if isinstance(items, list):
            pods = tuple(
                sorted(
                    (
                        _normalize_pod(item, index, errors)
                        for index, item in enumerate(items)
                    ),
                    key=lambda item: item.identity,
                )
            )
        else:
            errors.append("podList.items must be a list")

    completeness_issues = [f"{issue.operation}: {issue.message}" for issue in issues]
    if status != "complete":
        completeness_issues.append("Pod collection status is incomplete")
    if request is None:
        completeness_issues.append("Pod list-request provenance is missing")
    else:
        if request.namespace != scope.namespace:
            completeness_issues.append(
                "Pod list-request namespace does not match the Service"
            )
        if request.label_selector != "":
            completeness_issues.append(
                "Pod list request is not an unfiltered namespace snapshot"
            )
    if pods is None:
        completeness_issues.append("Pod list evidence is missing")
    else:
        if not resource_version:
            completeness_issues.append("Pod list has no resourceVersion snapshot")
        if continue_token:
            completeness_issues.append(
                "Pod list pagination is incomplete (continue token present)"
            )
        identities = [pod.identity for pod in pods]
        if len(identities) != len(set(identities)):
            completeness_issues.append("Pod identities are duplicated")
        uids = [pod.uid for pod in pods]
        if len(uids) != len(set(uids)):
            completeness_issues.append("Pod UIDs are duplicated")
        if any(pod.namespace != scope.namespace for pod in pods):
            completeness_issues.append(
                "Pod list contains Pods outside the requested namespace"
            )

    return PodEvidence(
        collection_status=status,
        collection_issues=issues,
        request=request,
        pods=pods,
        resource_version=resource_version,
        continue_token=continue_token,
        completeness_issues=tuple(completeness_issues),
    )


def normalize(raw: Mapping[str, Any]) -> EvidenceBundle:
    """Validate and normalize a source-neutral evidence envelope."""

    errors: list[str] = _ValidationErrors()
    if raw.get("schemaVersion") != EVIDENCE_SCHEMA_VERSION:
        errors.append(f"schemaVersion must be '{EVIDENCE_SCHEMA_VERSION}'")

    collection = _object(raw.get("collection"), "collection", errors)
    source = _safe_string(collection.get("source"), "collection.source", errors)
    source_collected_at, collected_at = _timestamp(
        collection.get("collectedAt"), "collection.collectedAt", errors
    )
    status = _required_string(collection.get("status"), "collection.status", errors)
    if status not in {"complete", "incomplete"}:
        errors.append("collection.status must be 'complete' or 'incomplete'")
    collection_issues = _normalize_collection_issues(
        collection.get("issues"), status, errors
    )

    scope_value = _object(collection.get("scope"), "collection.scope", errors)
    scope = CollectionScope(
        namespace=_dns_label(
            scope_value.get("namespace"), "collection.scope.namespace", errors
        ),
        service_name=_service_name(
            scope_value.get("serviceName"), "collection.scope.serviceName", errors
        ),
    )
    request_value = collection.get("endpointSliceListRequest")
    request: EndpointSliceRequest | None = None
    if request_value is not None:
        request_object = _object(
            request_value, "collection.endpointSliceListRequest", errors
        )
        request = EndpointSliceRequest(
            namespace=_optional_string(
                request_object.get("namespace"),
                "collection.endpointSliceListRequest.namespace",
                errors,
            ),
            label_selector=_optional_string(
                request_object.get("labelSelector"),
                "collection.endpointSliceListRequest.labelSelector",
                errors,
            ),
        )
    service_value = raw.get("service")
    service: Service | None
    if service_value is None and status == "incomplete" and collection_issues:
        service = None
    else:
        service = _normalize_service(service_value, errors)

    list_value = raw.get("endpointSliceList")
    endpoint_slices: tuple[EndpointSlice, ...] | None = None
    resource_version: str | None = None
    continue_token: str | None = None
    if list_value is not None:
        endpoint_list = _object(list_value, "endpointSliceList", errors)
        if endpoint_list.get("apiVersion") != "discovery.k8s.io/v1":
            errors.append("endpointSliceList.apiVersion must be 'discovery.k8s.io/v1'")
        if endpoint_list.get("kind") != "EndpointSliceList":
            errors.append("endpointSliceList.kind must be 'EndpointSliceList'")
        list_metadata = _object(
            endpoint_list.get("metadata"), "endpointSliceList.metadata", errors
        )
        resource_version = _optional_string(
            list_metadata.get("resourceVersion"),
            "endpointSliceList.metadata.resourceVersion",
            errors,
        )
        if resource_version is not None and not resource_version.isprintable():
            errors.append(
                "endpointSliceList.metadata.resourceVersion must be printable"
            )
        continue_token = _optional_string(
            list_metadata.get("continue"),
            "endpointSliceList.metadata.continue",
            errors,
        )
        if continue_token is not None and not continue_token.isprintable():
            errors.append("endpointSliceList.metadata.continue must be printable")
        items = endpoint_list.get("items")
        _validate_collection_limits(items)
        if isinstance(items, list):
            endpoint_slices = tuple(
                sorted(
                    (
                        _normalize_endpoint_slice(item, index, errors)
                        for index, item in enumerate(items)
                    ),
                    key=lambda item: item.identity,
                )
            )
        else:
            errors.append("endpointSliceList.items must be a list")

    pod_evidence = _normalize_pod_evidence(raw, collection, scope, errors)

    if errors:
        raise EvidenceValidationError(errors)

    completeness_issues: list[str] = []
    completeness_issues.extend(
        f"{issue.operation}: {issue.message}" for issue in collection_issues
    )
    if status != "complete":
        completeness_issues.append("collection status is incomplete")
    if service is not None and (
        scope.namespace != service.namespace or scope.service_name != service.name
    ):
        completeness_issues.append(
            "collection scope does not match the Service identity"
        )
    expected_selector = f"{SERVICE_NAME_LABEL}={scope.service_name}"
    if request is None:
        completeness_issues.append("EndpointSlice list-request provenance is missing")
    else:
        if request.namespace != scope.namespace:
            completeness_issues.append(
                "EndpointSlice list-request namespace does not match the Service"
            )
        if request.label_selector != expected_selector:
            completeness_issues.append(
                "EndpointSlice list-request label selector does not exactly match "
                "the Service"
            )
    if endpoint_slices is None:
        completeness_issues.append("EndpointSlice list evidence is missing")
    else:
        if not resource_version:
            completeness_issues.append(
                "EndpointSlice list has no resourceVersion snapshot"
            )
        if continue_token:
            completeness_issues.append(
                "EndpointSlice list pagination is incomplete (continue token present)"
            )
        identities = [item.identity for item in endpoint_slices]
        if len(identities) != len(set(identities)):
            completeness_issues.append("EndpointSlice identities are duplicated")
        for item in endpoint_slices:
            if (
                item.namespace != scope.namespace
                or item.service_name != scope.service_name
            ):
                completeness_issues.append(
                    f"EndpointSlice {item.identity} is not associated with "
                    f"Service {scope.namespace}/{scope.service_name}"
                )

    return EvidenceBundle(
        source=source,
        source_collected_at=source_collected_at,
        collected_at=collected_at,
        collection_status=status,
        scope=scope,
        collection_issues=collection_issues,
        endpoint_slice_request=request,
        service=service,
        endpoint_slices=endpoint_slices,
        endpoint_slice_resource_version=resource_version,
        endpoint_slice_continue=continue_token,
        completeness_issues=tuple(completeness_issues),
        pod_evidence=pod_evidence,
    )


def _endpoint_records(
    endpoint_slices: tuple[EndpointSlice, ...],
) -> tuple[dict[tuple[str, str], set[bool | None]], int]:
    readiness_by_identity: dict[tuple[str, str], set[bool | None]] = {}
    record_count = 0
    for endpoint_slice in endpoint_slices:
        for endpoint in endpoint_slice.endpoints:
            record_count += 1
            readiness_by_identity.setdefault(endpoint.identity, set()).add(
                endpoint.ready
            )
    return readiness_by_identity, record_count


def _selectorless_causes(
    slice_count: int, endpoint_count: int, unready_count: int
) -> tuple[str, ...]:
    if slice_count == 0:
        return (
            "EndpointSlices may not have been configured for the selectorless Service.",
        )
    if endpoint_count == 0:
        return ("The observed EndpointSlices are configured without endpoints.",)
    if unready_count == 1:
        return ("The manually managed endpoint is explicitly unready.",)
    return (f"All {unready_count} manually managed endpoints are explicitly unready.",)


def _pod_matches_selector(pod: Pod, service: Service) -> bool:
    labels = dict(pod.labels)
    return all(labels.get(key) == value for key, value in service.selector or ())


def _pod_cause_analysis(
    evidence: EvidenceBundle, service: Service
) -> tuple[
    tuple[ObservedEvidence, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    pod_evidence = evidence.pod_evidence
    default_causes = (
        "No matching Pods may exist.",
        "The Service selector may not match the intended Pods.",
        "Matching Pods may be failing readiness checks.",
        "EndpointSlice controller data may not have converged.",
    )
    if pod_evidence is None:
        return (
            (),
            (),
            default_causes,
            (),
            ("The observed condition does not independently confirm its cause.",),
        )
    if pod_evidence.completeness_issues:
        return (
            (),
            (),
            default_causes,
            (),
            (
                "Pod cause evidence is incomplete, so no endpoint cause is confirmed.",
                *pod_evidence.completeness_issues,
            ),
        )

    pods = pod_evidence.pods or ()
    matching = tuple(pod for pod in pods if _pod_matches_selector(pod, service))
    ready_count = sum(pod.ready is True for pod in matching)
    unready_count = sum(pod.ready is False for pod in matching)
    unknown_count = sum(pod.ready is None for pod in matching)
    observation = ObservedEvidence(
        statement=(
            f"Complete namespace Pod snapshot contains {len(pods)} Pods; "
            f"{len(matching)} match the Service selector: {ready_count} ready, "
            f"{unready_count} unready, {unknown_count} unknown readiness"
        ),
        source=evidence.source,
        source_collected_at=evidence.source_collected_at,
        collected_at=evidence.collected_at,
        resource=(
            f"PodList/{evidence.scope.namespace}@{pod_evidence.resource_version}"
        ),
        transformations=(
            f"validated against {EVIDENCE_SCHEMA_VERSION}",
            "matched projected Pod labels against the observed Service selector",
        ),
    )
    snapshot_limitation = (
        "Service, EndpointSlice, and Pod reads are not an atomic cross-resource "
        "snapshot."
    )

    if not pods:
        return (
            (observation,),
            ("The complete namespace-scoped Pod snapshot contains no Pods.",),
            ("No workload may currently be creating Pods in the namespace.",),
            (),
            (
                "The observations do not establish why the namespace has no Pods.",
                snapshot_limitation,
            ),
        )
    if not matching:
        return (
            (observation,),
            (
                f"The Service selector matches none of the {len(pods)} Pods in the "
                "complete namespace-scoped snapshot.",
            ),
            ("The Service selector may not match the intended Pods.",),
            (),
            (
                "The evidence does not establish which Pods, if any, were intended "
                "for the Service.",
                snapshot_limitation,
            ),
        )
    if ready_count:
        return (
            (observation,),
            (
                "At least one Pod matching the Service selector explicitly reports "
                "Ready=True.",
            ),
            ("EndpointSlice controller data may not have converged.",),
            (),
            (
                "Pod readiness and EndpointSlice readiness are inconsistent, so no "
                "endpoint cause is confirmed.",
                snapshot_limitation,
            ),
        )
    if unknown_count:
        return (
            (observation,),
            (),
            (
                "Matching Pods may be unready, but one or more Pod Ready conditions "
                "are unknown.",
            ),
            (),
            (
                "Pod readiness is missing or unknown, so an unready-Pod cause cannot "
                "be established.",
                snapshot_limitation,
            ),
        )
    return (
        (observation,),
        (
            f"All {len(matching)} Pods matching the Service selector explicitly "
            "report Ready=False.",
        ),
        ("Matching Pods may be failing readiness checks.",),
        (
            f"All {len(matching)} Pods matching the Service selector explicitly "
            "reported Ready=False during the bounded collection.",
        ),
        (
            "The evidence establishes the immediate readiness condition, not why the "
            "Pods are unready.",
            snapshot_limitation,
        ),
    )


def evaluate_service_no_ready_endpoints(
    evidence: EvidenceBundle,
) -> DiagnosticReport:
    """Evaluate SERVICE_NO_READY_ENDPOINTS from normalized evidence."""

    service = evidence.service
    pod_issues = (
        evidence.pod_evidence.collection_issues
        if evidence.pod_evidence is not None
        else ()
    )
    collection_issues = (*evidence.collection_issues, *pod_issues)
    if service is None:
        identity = f"{evidence.scope.namespace}/{evidence.scope.service_name}"
        return DiagnosticReport(
            rule_id=RULE_ID,
            outcome=Outcome.INCONCLUSIVE,
            summary=f"{RULE_ID}: inconclusive for requested Service {identity}",
            target=evidence.scope,
            service=None,
            collection_issues=collection_issues,
            observed_evidence=(),
            derived_findings=(),
            possible_causes=(),
            confirmed_causes=(),
            limitations=evidence.completeness_issues,
        )
    service_observation = ObservedEvidence(
        statement=(
            f"Service type is {service.service_type}; "
            f"selector is {'absent' if service.selector is None else 'present'}"
        ),
        source=evidence.source,
        source_collected_at=evidence.source_collected_at,
        collected_at=evidence.collected_at,
        resource=f"Service/{service.identity} (uid={service.uid})",
        transformations=(
            f"validated against {EVIDENCE_SCHEMA_VERSION}",
            "normalized to KubeTrace domain models",
        ),
    )

    if service.service_type == "ExternalName":
        return DiagnosticReport(
            rule_id=RULE_ID,
            outcome=Outcome.NOT_APPLICABLE,
            summary=f"{RULE_ID}: not applicable to ExternalName {service.identity}",
            target=evidence.scope,
            service=service,
            collection_issues=collection_issues,
            observed_evidence=(service_observation,),
            derived_findings=(
                "ExternalName Services do not use EndpointSlices for this rule.",
            ),
            possible_causes=(),
            confirmed_causes=(),
            limitations=(),
        )

    if evidence.completeness_issues:
        return DiagnosticReport(
            rule_id=RULE_ID,
            outcome=Outcome.INCONCLUSIVE,
            summary=f"{RULE_ID}: inconclusive for Service {service.identity}",
            target=evidence.scope,
            service=service,
            collection_issues=collection_issues,
            observed_evidence=(service_observation,),
            derived_findings=(),
            possible_causes=(),
            confirmed_causes=(),
            limitations=evidence.completeness_issues,
        )

    endpoint_slices = evidence.endpoint_slices or ()
    readiness_by_identity, record_count = _endpoint_records(endpoint_slices)
    conflicts = tuple(
        sorted(
            identity
            for identity, states in readiness_by_identity.items()
            if len(states) > 1
        )
    )
    ready_count = sum(states == {True} for states in readiness_by_identity.values())
    unready_count = sum(states == {False} for states in readiness_by_identity.values())
    unknown_count = sum(states == {None} for states in readiness_by_identity.values())
    endpoint_observation = ObservedEvidence(
        statement=(
            f"Complete EndpointSlice snapshot contains {len(endpoint_slices)} slices, "
            f"{record_count} endpoint records, and {len(readiness_by_identity)} unique "
            f"logical endpoints: {ready_count} ready, {unready_count} unready, "
            f"{unknown_count} unknown readiness"
        ),
        source=evidence.source,
        source_collected_at=evidence.source_collected_at,
        collected_at=evidence.collected_at,
        resource=(
            "EndpointSliceList/"
            f"{service.identity}@{evidence.endpoint_slice_resource_version}"
        ),
        transformations=(
            f"validated against {EVIDENCE_SCHEMA_VERSION}",
            "canonicalized and deduplicated logical endpoint identities",
        ),
    )
    observations = (service_observation, endpoint_observation)

    if conflicts:
        rendered = ", ".join(f"{kind}:{address}" for kind, address in conflicts)
        return DiagnosticReport(
            rule_id=RULE_ID,
            outcome=Outcome.INCONCLUSIVE,
            summary=f"{RULE_ID}: inconclusive for Service {service.identity}",
            target=evidence.scope,
            service=service,
            collection_issues=collection_issues,
            observed_evidence=observations,
            derived_findings=(),
            possible_causes=(),
            confirmed_causes=(),
            limitations=(
                f"Conflicting readiness was reported for logical endpoints: {rendered}",
            ),
        )

    if ready_count:
        unknown_label = "endpoint has" if unknown_count == 1 else "endpoints have"
        return DiagnosticReport(
            rule_id=RULE_ID,
            outcome=Outcome.NO_FINDING,
            summary=f"{RULE_ID}: no finding for Service {service.identity}",
            target=evidence.scope,
            service=service,
            collection_issues=collection_issues,
            observed_evidence=observations,
            derived_findings=("At least one logical endpoint is explicitly ready.",),
            possible_causes=(),
            confirmed_causes=(),
            limitations=(
                (f"{unknown_count} {unknown_label} unknown readiness.",)
                if unknown_count
                else ()
            ),
        )

    if unknown_count:
        return DiagnosticReport(
            rule_id=RULE_ID,
            outcome=Outcome.INCONCLUSIVE,
            summary=f"{RULE_ID}: inconclusive for Service {service.identity}",
            target=evidence.scope,
            service=service,
            collection_issues=collection_issues,
            observed_evidence=observations,
            derived_findings=(),
            possible_causes=(),
            confirmed_causes=(),
            limitations=(
                "Endpoint readiness is missing or unknown, so zero ready endpoints "
                "cannot be established.",
            ),
        )

    if service.selector is None:
        possible_causes = _selectorless_causes(
            len(endpoint_slices), len(readiness_by_identity), unready_count
        )
        pod_observations: tuple[ObservedEvidence, ...] = ()
        pod_findings: tuple[str, ...] = ()
        confirmed_causes: tuple[str, ...] = ()
        limitations = (
            "The observed condition does not independently confirm its cause.",
        )
    else:
        (
            pod_observations,
            pod_findings,
            possible_causes,
            confirmed_causes,
            limitations,
        ) = _pod_cause_analysis(evidence, service)
    return DiagnosticReport(
        rule_id=RULE_ID,
        outcome=Outcome.FINDING,
        summary=f"{RULE_ID}: Service {service.identity} has no ready endpoints",
        target=evidence.scope,
        service=service,
        collection_issues=collection_issues,
        observed_evidence=(*observations, *pod_observations),
        derived_findings=(
            "The complete associated EndpointSlice snapshot contains zero "
            "explicitly ready logical endpoints.",
            *pod_findings,
        ),
        possible_causes=possible_causes,
        confirmed_causes=confirmed_causes,
        limitations=limitations,
    )


def run_diagnostic(collector: EvidenceCollector) -> DiagnosticReport:
    """Run the collector, normalization, and rule pipeline."""

    return evaluate_service_no_ready_endpoints(normalize(collector.collect()))
