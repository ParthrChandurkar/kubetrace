"""Evidence collection, normalization, and deterministic rule evaluation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path
from typing import Any, Protocol

from kubetrace.explainability import explain_report
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
    Flow,
    FlowEndpoint,
    FlowEvidence,
    IPBlock,
    LabelSelector,
    LabelSelectorRequirement,
    NetworkPolicy,
    NetworkPolicyEvidence,
    NetworkPolicyListRequest,
    NetworkPolicyPeer,
    NetworkPolicyPort,
    NetworkPolicyRule,
    ObservedEvidence,
    Outcome,
    Pod,
    PodEvidence,
    PodListRequest,
    Service,
    TrafficContext,
    TrafficPeer,
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
MAX_NETWORK_POLICIES = 256
MAX_NETWORK_POLICY_RULES = 2_048
MAX_NETWORK_POLICY_RULE_ENTRIES = 10_000
MAX_FLOWS = 1_000
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
    projected_label_keys: tuple[str, ...] | None = None
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
        keys_value = request_object.get("projectedLabelKeys")
        if keys_value is not None:
            if not isinstance(keys_value, list) or not all(
                isinstance(key, str) and key and key.isprintable() for key in keys_value
            ):
                errors.append(
                    "collection.podListCollection.request.projectedLabelKeys must "
                    "be a list of non-empty printable strings"
                )
            else:
                projected_label_keys = tuple(sorted(set(keys_value)))

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
        projected_label_keys=projected_label_keys,
    )


def _normalize_label_map(
    value: Any, path: str, errors: list[str]
) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return ()
    labels: list[tuple[str, str]] = []
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 253
            or not key.isprintable()
        ):
            errors.append(
                f"{path} keys must be non-empty printable strings of at most 253 "
                "characters"
            )
            continue
        if not isinstance(item, str) or len(item) > 63 or not item.isprintable():
            errors.append(
                f"{path}.{key} must be a printable string of at most 63 characters"
            )
            continue
        labels.append((key, item))
    return tuple(sorted(labels))


def _normalize_label_selector(
    value: Any, path: str, errors: list[str]
) -> LabelSelector:
    selector = _object(value, path, errors)
    match_labels = _normalize_label_map(
        selector.get("matchLabels"), f"{path}.matchLabels", errors
    )
    expressions_value = selector.get("matchExpressions", [])
    expressions: list[LabelSelectorRequirement] = []
    if not isinstance(expressions_value, list):
        errors.append(f"{path}.matchExpressions must be a list")
    else:
        for index, item in enumerate(expressions_value):
            item_path = f"{path}.matchExpressions[{index}]"
            expression = _object(item, item_path, errors)
            key = _safe_string(
                expression.get("key"),
                f"{item_path}.key",
                errors,
                max_length=253,
            )
            operator = _required_string(
                expression.get("operator"), f"{item_path}.operator", errors
            )
            values_value = expression.get("values", [])
            values: tuple[str, ...] = ()
            if not isinstance(values_value, list) or not all(
                isinstance(entry, str) and len(entry) <= 63 and entry.isprintable()
                for entry in values_value
            ):
                errors.append(f"{item_path}.values must be a list of printable strings")
            else:
                values = tuple(sorted(values_value))
            if operator not in {"In", "NotIn", "Exists", "DoesNotExist"}:
                errors.append(
                    f"{item_path}.operator must be In, NotIn, Exists, or DoesNotExist"
                )
            elif operator in {"In", "NotIn"} and not values:
                errors.append(f"{item_path}.values must not be empty for {operator}")
            elif operator in {"Exists", "DoesNotExist"} and values:
                errors.append(f"{item_path}.values must be empty for {operator}")
            expressions.append(LabelSelectorRequirement(key, operator, values))
    return LabelSelector(match_labels, tuple(sorted(expressions, key=repr)))


def _normalize_policy_port(
    value: Any, path: str, errors: list[str]
) -> NetworkPolicyPort:
    item = _object(value, path, errors)
    protocol = item.get("protocol", "TCP")
    if protocol not in {"TCP", "UDP", "SCTP"}:
        errors.append(f"{path}.protocol must be TCP, UDP, or SCTP")
        protocol = "TCP"
    port = item.get("port")
    if port is not None and (
        isinstance(port, bool)
        or not isinstance(port, int | str)
        or isinstance(port, int)
        and not 1 <= port <= 65535
        or isinstance(port, str)
        and (not port or not port.isprintable())
    ):
        errors.append(f"{path}.port must be a valid integer or named port")
        port = None
    end_port = item.get("endPort")
    if end_port is not None and (
        isinstance(end_port, bool)
        or not isinstance(end_port, int)
        or not isinstance(port, int)
        or not port <= end_port <= 65535
    ):
        errors.append(f"{path}.endPort requires a numeric port and valid range")
        end_port = None
    return NetworkPolicyPort(protocol, port, end_port)


def _normalize_ip_block(value: Any, path: str, errors: list[str]) -> IPBlock:
    item = _object(value, path, errors)
    cidr = _required_string(item.get("cidr"), f"{path}.cidr", errors)
    network = None
    try:
        network = ip_network(cidr, strict=True)
    except ValueError:
        errors.append(f"{path}.cidr must be a canonical IPv4 or IPv6 network")
    except TypeError:
        pass
    exceptions_value = item.get("except", [])
    exceptions: list[str] = []
    if not isinstance(exceptions_value, list):
        errors.append(f"{path}.except must be a list")
    else:
        for index, exception in enumerate(exceptions_value):
            try:
                parsed = ip_network(exception, strict=True)
            except (TypeError, ValueError):
                errors.append(f"{path}.except[{index}] must be a canonical IP network")
                continue
            if network is not None and (
                parsed.version != network.version or not parsed.subnet_of(network)
            ):
                errors.append(f"{path}.except[{index}] must be within {cidr}")
            exceptions.append(str(parsed))
    return IPBlock(cidr, tuple(sorted(exceptions)))


def _normalize_policy_peer(
    value: Any, path: str, errors: list[str]
) -> NetworkPolicyPeer:
    item = _object(value, path, errors)
    pod_value = item.get("podSelector")
    namespace_value = item.get("namespaceSelector")
    ip_value = item.get("ipBlock")
    if ip_value is not None and (pod_value is not None or namespace_value is not None):
        errors.append(f"{path}.ipBlock cannot be combined with label selectors")
    return NetworkPolicyPeer(
        _normalize_label_selector(pod_value, f"{path}.podSelector", errors)
        if pod_value is not None
        else None,
        _normalize_label_selector(namespace_value, f"{path}.namespaceSelector", errors)
        if namespace_value is not None
        else None,
        _normalize_ip_block(ip_value, f"{path}.ipBlock", errors)
        if ip_value is not None
        else None,
    )


def _normalize_policy_rule(
    value: Any, path: str, peer_field: str, errors: list[str]
) -> NetworkPolicyRule:
    item = _object(value, path, errors)
    peers_value = item.get(peer_field, [])
    ports_value = item.get("ports", [])
    if not isinstance(peers_value, list):
        errors.append(f"{path}.{peer_field} must be a list")
        peers: tuple[NetworkPolicyPeer, ...] = ()
    else:
        peers = tuple(
            _normalize_policy_peer(peer, f"{path}.{peer_field}[{index}]", errors)
            for index, peer in enumerate(peers_value)
        )
    if not isinstance(ports_value, list):
        errors.append(f"{path}.ports must be a list")
        ports: tuple[NetworkPolicyPort, ...] = ()
    else:
        ports = tuple(
            _normalize_policy_port(port, f"{path}.ports[{index}]", errors)
            for index, port in enumerate(ports_value)
        )
    return NetworkPolicyRule(peers, ports)


def _normalize_network_policy(
    value: Any, index: int, errors: list[str]
) -> NetworkPolicy:
    path = f"networkPolicyList.items[{index}]"
    item = _object(value, path, errors)
    if item.get("apiVersion") != "networking.k8s.io/v1":
        errors.append(f"{path}.apiVersion must be 'networking.k8s.io/v1'")
    if item.get("kind") != "NetworkPolicy":
        errors.append(f"{path}.kind must be 'NetworkPolicy'")
    metadata = _object(item.get("metadata"), f"{path}.metadata", errors)
    spec = _object(item.get("spec"), f"{path}.spec", errors)
    ingress_value = spec.get("ingress", [])
    egress_value = spec.get("egress", [])
    ingress = (
        tuple(
            _normalize_policy_rule(
                rule, f"{path}.spec.ingress[{rule_index}]", "from", errors
            )
            for rule_index, rule in enumerate(ingress_value)
        )
        if isinstance(ingress_value, list)
        else ()
    )
    egress = (
        tuple(
            _normalize_policy_rule(
                rule, f"{path}.spec.egress[{rule_index}]", "to", errors
            )
            for rule_index, rule in enumerate(egress_value)
        )
        if isinstance(egress_value, list)
        else ()
    )
    if not isinstance(ingress_value, list):
        errors.append(f"{path}.spec.ingress must be a list")
    if not isinstance(egress_value, list):
        errors.append(f"{path}.spec.egress must be a list")
    types_value = spec.get("policyTypes")
    if types_value is None:
        policy_types = ("Ingress", "Egress") if egress else ("Ingress",)
    elif not isinstance(types_value, list) or not all(
        item_type in {"Ingress", "Egress"} for item_type in types_value
    ):
        errors.append(f"{path}.spec.policyTypes must contain Ingress or Egress")
        policy_types = ()
    else:
        policy_types = tuple(sorted(set(types_value)))
        if len(policy_types) != len(types_value):
            errors.append(f"{path}.spec.policyTypes must not contain duplicates")
    return NetworkPolicy(
        namespace=_dns_label(
            metadata.get("namespace"), f"{path}.metadata.namespace", errors
        ),
        name=_dns_subdomain(metadata.get("name"), f"{path}.metadata.name", errors),
        uid=_safe_string(metadata.get("uid"), f"{path}.metadata.uid", errors),
        pod_selector=_normalize_label_selector(
            spec.get("podSelector"), f"{path}.spec.podSelector", errors
        ),
        policy_types=policy_types,
        ingress=ingress,
        egress=egress,
    )


def _normalize_network_policy_evidence(
    raw: Mapping[str, Any],
    collection: dict[str, Any],
    scope: CollectionScope,
    errors: list[str],
) -> NetworkPolicyEvidence | None:
    collection_value = collection.get("networkPolicyListCollection")
    list_value = raw.get("networkPolicyList")
    if collection_value is None and list_value is None:
        return None
    policy_collection = _object(
        collection_value, "collection.networkPolicyListCollection", errors
    )
    status = _required_string(
        policy_collection.get("status"),
        "collection.networkPolicyListCollection.status",
        errors,
    )
    if status not in {"complete", "incomplete"}:
        errors.append(
            "collection.networkPolicyListCollection.status must be complete or "
            "incomplete"
        )
    issues = _normalize_collection_issues(
        policy_collection.get("issues"),
        status,
        errors,
        path="collection.networkPolicyListCollection.issues",
    )
    request_value = policy_collection.get("request")
    request = None
    if request_value is not None:
        request_object = _object(
            request_value, "collection.networkPolicyListCollection.request", errors
        )
        request = NetworkPolicyListRequest(
            namespace=_optional_string(
                request_object.get("namespace"),
                "collection.networkPolicyListCollection.request.namespace",
                errors,
            )
        )
    policies: tuple[NetworkPolicy, ...] | None = None
    resource_version: str | None = None
    continue_token: str | None = None
    if list_value is not None:
        policy_list = _object(list_value, "networkPolicyList", errors)
        if policy_list.get("apiVersion") != "networking.k8s.io/v1":
            errors.append("networkPolicyList.apiVersion must be 'networking.k8s.io/v1'")
        if policy_list.get("kind") != "NetworkPolicyList":
            errors.append("networkPolicyList.kind must be 'NetworkPolicyList'")
        metadata = _object(
            policy_list.get("metadata"), "networkPolicyList.metadata", errors
        )
        resource_version = _optional_string(
            metadata.get("resourceVersion"),
            "networkPolicyList.metadata.resourceVersion",
            errors,
        )
        continue_token = _optional_string(
            metadata.get("continue"), "networkPolicyList.metadata.continue", errors
        )
        if resource_version is not None and not resource_version.isprintable():
            errors.append(
                "networkPolicyList.metadata.resourceVersion must be printable"
            )
        if continue_token is not None and not continue_token.isprintable():
            errors.append("networkPolicyList.metadata.continue must be printable")
        items = policy_list.get("items")
        if isinstance(items, list):
            if len(items) > MAX_NETWORK_POLICIES:
                raise EvidenceValidationError(
                    [
                        "NetworkPolicy count exceeds the "
                        f"{MAX_NETWORK_POLICIES}-policy limit"
                    ]
                )
            policies = tuple(
                sorted(
                    (
                        _normalize_network_policy(item, index, errors)
                        for index, item in enumerate(items)
                    ),
                    key=lambda policy: policy.identity,
                )
            )
            rule_count = sum(
                len(policy.ingress) + len(policy.egress) for policy in policies
            )
            if rule_count > MAX_NETWORK_POLICY_RULES:
                raise EvidenceValidationError(
                    [
                        "NetworkPolicy rule count exceeds the "
                        f"{MAX_NETWORK_POLICY_RULES}-rule limit"
                    ]
                )
            entry_count = sum(
                len(rule.peers) + len(rule.ports)
                for policy in policies
                for rule in (*policy.ingress, *policy.egress)
            )
            if entry_count > MAX_NETWORK_POLICY_RULE_ENTRIES:
                raise EvidenceValidationError(
                    [
                        "NetworkPolicy peer and port count exceeds the "
                        f"{MAX_NETWORK_POLICY_RULE_ENTRIES}-entry limit"
                    ]
                )
        else:
            errors.append("networkPolicyList.items must be a list")
    completeness = [f"{issue.operation}: {issue.message}" for issue in issues]
    if status != "complete":
        completeness.append("NetworkPolicy collection status is incomplete")
    if request is None:
        completeness.append("NetworkPolicy list-request provenance is missing")
    elif request.namespace != scope.namespace:
        completeness.append(
            "NetworkPolicy list-request namespace does not match the Service"
        )
    if policies is None:
        completeness.append("NetworkPolicy list evidence is missing")
    else:
        if not resource_version:
            completeness.append("NetworkPolicy list has no resourceVersion snapshot")
        if continue_token:
            completeness.append(
                "NetworkPolicy list pagination is incomplete (continue token present)"
            )
        identities = [policy.identity for policy in policies]
        if len(identities) != len(set(identities)):
            completeness.append("NetworkPolicy identities are duplicated")
        uids = [policy.uid for policy in policies]
        if len(uids) != len(set(uids)):
            completeness.append("NetworkPolicy UIDs are duplicated")
        if any(policy.namespace != scope.namespace for policy in policies):
            completeness.append(
                "NetworkPolicy list contains policies outside the requested namespace"
            )
    return NetworkPolicyEvidence(
        status,
        issues,
        request,
        policies,
        resource_version,
        continue_token,
        tuple(completeness),
    )


def _normalize_traffic(
    raw: Mapping[str, Any], errors: list[str]
) -> TrafficContext | None:
    value = raw.get("traffic")
    if value is None:
        return None
    item = _object(value, "traffic", errors)
    direction = _required_string(item.get("direction"), "traffic.direction", errors)
    if direction not in {"ingress", "egress"}:
        errors.append("traffic.direction must be ingress or egress")
    protocol = _required_string(item.get("protocol"), "traffic.protocol", errors)
    if protocol not in {"TCP", "UDP", "SCTP"}:
        errors.append("traffic.protocol must be TCP, UDP, or SCTP")
    port = item.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        errors.append("traffic.port must be an integer from 1 to 65535")
        port = 0
    peer_value = _object(item.get("peer"), "traffic.peer", errors)
    namespace = _optional_string(
        peer_value.get("namespace"), "traffic.peer.namespace", errors
    )
    ip_value = _optional_string(peer_value.get("ip"), "traffic.peer.ip", errors)
    if ip_value is not None:
        try:
            ip_value = str(ip_address(ip_value))
        except ValueError:
            errors.append("traffic.peer.ip must be a valid IP address")
    namespace_labels = (
        _normalize_label_map(
            peer_value.get("namespaceLabels"),
            "traffic.peer.namespaceLabels",
            errors,
        )
        if "namespaceLabels" in peer_value
        else None
    )
    pod_labels = (
        _normalize_label_map(
            peer_value.get("podLabels"), "traffic.peer.podLabels", errors
        )
        if "podLabels" in peer_value
        else None
    )
    return TrafficContext(
        direction,
        protocol,
        port,
        TrafficPeer(namespace, namespace_labels, pod_labels, ip_value),
    )


def _normalize_flow_endpoint(value: Any, path: str, errors: list[str]) -> FlowEndpoint:
    item = _object(value, path, errors)
    namespace = _optional_string(item.get("namespace"), f"{path}.namespace", errors)
    pod_name = _optional_string(item.get("pod"), f"{path}.pod", errors)
    identity = item.get("identity")
    if identity is not None and (
        isinstance(identity, bool) or not isinstance(identity, int)
    ):
        errors.append(f"{path}.identity must be an integer or null")
        identity = None
    ip_value = _optional_string(item.get("ip"), f"{path}.ip", errors)
    if ip_value:
        try:
            ip_value = str(ip_address(ip_value))
        except ValueError:
            errors.append(f"{path}.ip must be a valid IP address")
    return FlowEndpoint(namespace, pod_name, identity, ip_value)


def _normalize_flow_evidence(
    raw: Mapping[str, Any], collection: dict[str, Any], errors: list[str]
) -> FlowEvidence | None:
    collection_value = collection.get("hubbleFlowCollection")
    flows_value = raw.get("flows")
    if collection_value is None and flows_value is None:
        return None
    item = _object(collection_value, "collection.hubbleFlowCollection", errors)
    status = _required_string(
        item.get("status"), "collection.hubbleFlowCollection.status", errors
    )
    if status not in {"complete", "incomplete"}:
        errors.append(
            "collection.hubbleFlowCollection.status must be complete or incomplete"
        )
    issues = _normalize_collection_issues(
        item.get("issues"),
        status,
        errors,
        path="collection.hubbleFlowCollection.issues",
    )
    window = _object(
        item.get("window"), "collection.hubbleFlowCollection.window", errors
    )
    start_source, start = _timestamp(
        window.get("start"), "collection.hubbleFlowCollection.window.start", errors
    )
    end_source, end = _timestamp(
        window.get("end"), "collection.hubbleFlowCollection.window.end", errors
    )
    del start_source, end_source
    truncated = item.get("truncated", False)
    if not isinstance(truncated, bool):
        errors.append("collection.hubbleFlowCollection.truncated must be a boolean")
        truncated = True
    if not isinstance(flows_value, list):
        errors.append("flows must be a list")
        flows_value = []
    if len(flows_value) > MAX_FLOWS:
        raise EvidenceValidationError(
            [f"flow count exceeds the {MAX_FLOWS}-flow limit"]
        )
    flows: list[Flow] = []
    for index, value in enumerate(flows_value):
        path = f"flows[{index}]"
        flow = _object(value, path, errors)
        _, timestamp = _timestamp(flow.get("timestamp"), f"{path}.timestamp", errors)
        verdict = _safe_string(flow.get("verdict"), f"{path}.verdict", errors).upper()
        direction = _optional_string(flow.get("direction"), f"{path}.direction", errors)
        if direction is not None and direction not in {"ingress", "egress"}:
            errors.append(f"{path}.direction must be ingress, egress, or null")
        protocol = _optional_string(flow.get("protocol"), f"{path}.protocol", errors)
        if protocol is not None:
            protocol = protocol.upper()
            if protocol not in {"TCP", "UDP", "SCTP", "ICMP", "ICMPV6"}:
                errors.append(f"{path}.protocol is unsupported")
        ports: list[int | None] = []
        for field in ("sourcePort", "destinationPort"):
            port = flow.get(field)
            if port is not None and (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 0 <= port <= 65535
            ):
                errors.append(
                    f"{path}.{field} must be an integer from 0 to 65535 or null"
                )
                port = None
            ports.append(port)
        policy_related = flow.get("policyRelated")
        if policy_related is not None and not isinstance(policy_related, bool):
            errors.append(f"{path}.policyRelated must be a boolean or null")
            policy_related = None
        flows.append(
            Flow(
                timestamp,
                verdict,
                direction,
                _normalize_flow_endpoint(flow.get("source"), f"{path}.source", errors),
                _normalize_flow_endpoint(
                    flow.get("destination"), f"{path}.destination", errors
                ),
                protocol,
                ports[0],
                ports[1],
                _optional_string(flow.get("dropReason"), f"{path}.dropReason", errors),
                policy_related,
            )
        )
    unique = {flow: None for flow in flows}
    normalized = tuple(sorted(unique, key=lambda flow: (flow.timestamp, repr(flow))))
    completeness = [f"{issue.operation}: {issue.message}" for issue in issues]
    verdicts_by_identity: dict[tuple[Any, ...], set[str]] = {}
    for flow in normalized:
        identity = (
            flow.timestamp,
            flow.direction,
            flow.source,
            flow.destination,
            flow.protocol,
            flow.source_port,
            flow.destination_port,
        )
        verdicts_by_identity.setdefault(identity, set()).add(flow.verdict)
    if any(len(verdicts) > 1 for verdicts in verdicts_by_identity.values()):
        completeness.append("Hubble flow records contain contradictory verdicts")
    if status != "complete":
        completeness.append("Hubble flow collection status is incomplete")
    if truncated:
        completeness.append("Hubble flow collection was truncated")
    if start and end and _normalized_datetime(start) >= _normalized_datetime(end):
        completeness.append("Hubble collection window is not increasing")
    return FlowEvidence(
        status,
        issues,
        start or None,
        end or None,
        normalized,
        truncated,
        tuple(completeness),
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
    network_policy_evidence = _normalize_network_policy_evidence(
        raw, collection, scope, errors
    )
    traffic = _normalize_traffic(raw, errors)
    flow_evidence = _normalize_flow_evidence(raw, collection, errors)

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
        network_policy_evidence=network_policy_evidence,
        traffic=traffic,
        flow_evidence=flow_evidence,
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


def _selector_keys(selector: LabelSelector) -> set[str]:
    return {
        *(key for key, _value in selector.match_labels),
        *(requirement.key for requirement in selector.match_expressions),
    }


def _label_selector_matches(
    selector: LabelSelector, labels: tuple[tuple[str, str], ...]
) -> bool:
    values = dict(labels)
    if any(values.get(key) != expected for key, expected in selector.match_labels):
        return False
    for requirement in selector.match_expressions:
        present = requirement.key in values
        value = values.get(requirement.key)
        if requirement.operator == "In" and (
            not present or value not in requirement.values
        ):
            return False
        if requirement.operator == "NotIn" and (
            not present or value in requirement.values
        ):
            return False
        if requirement.operator == "Exists" and not present:
            return False
        if requirement.operator == "DoesNotExist" and present:
            return False
    return True


def _label_selector_is_empty(selector: LabelSelector) -> bool:
    return not selector.match_labels and not selector.match_expressions


def _policy_port_matches(
    port: NetworkPolicyPort, traffic: TrafficContext
) -> bool | None:
    if port.protocol != traffic.protocol:
        return False
    if port.port is None:
        return True
    if isinstance(port.port, str):
        return None
    return port.port <= traffic.port <= (port.end_port or port.port)


def _policy_peer_matches(
    peer: NetworkPolicyPeer,
    traffic: TrafficContext,
    policy_namespace: str,
) -> bool | None:
    traffic_peer = traffic.peer
    if peer.ip_block is not None:
        if traffic_peer.ip is None:
            return None
        address = ip_address(traffic_peer.ip)
        network = ip_network(peer.ip_block.cidr)
        if address not in network:
            return False
        return not any(
            address in ip_network(exception) for exception in peer.ip_block.exceptions
        )
    if peer.namespace_selector is not None:
        if not _label_selector_is_empty(peer.namespace_selector):
            if traffic_peer.namespace_labels is None:
                return None
            if not _label_selector_matches(
                peer.namespace_selector, traffic_peer.namespace_labels
            ):
                return False
    elif peer.pod_selector is not None:
        if traffic_peer.namespace is None:
            return None
        if traffic_peer.namespace != policy_namespace:
            return False
    if peer.pod_selector is not None:
        if not _label_selector_is_empty(peer.pod_selector):
            if traffic_peer.pod_labels is None:
                return None
            if not _label_selector_matches(peer.pod_selector, traffic_peer.pod_labels):
                return False
    return True


def _policy_rule_matches(
    rule: NetworkPolicyRule,
    traffic: TrafficContext,
    policy_namespace: str,
) -> bool | None:
    port_results = (
        tuple(_policy_port_matches(port, traffic) for port in rule.ports)
        if rule.ports
        else (True,)
    )
    if not any(result is True for result in port_results):
        return None if any(result is None for result in port_results) else False
    peer_results = (
        tuple(
            _policy_peer_matches(peer, traffic, policy_namespace) for peer in rule.peers
        )
        if rule.peers
        else (True,)
    )
    if any(result is True for result in peer_results):
        return True
    return None if any(result is None for result in peer_results) else False


def _pod_policy_result(
    pod: Pod,
    policies: tuple[NetworkPolicy, ...],
    traffic: TrafficContext,
) -> tuple[bool | None, tuple[NetworkPolicy, ...]]:
    policy_type = traffic.direction.capitalize()
    selected = tuple(
        policy
        for policy in policies
        if policy_type in policy.policy_types
        and _label_selector_matches(policy.pod_selector, pod.labels)
    )
    if not selected:
        return True, ()
    results = tuple(
        _policy_rule_matches(rule, traffic, policy.namespace)
        for policy in selected
        for rule in (
            policy.ingress if traffic.direction == "ingress" else policy.egress
        )
    )
    if any(result is True for result in results):
        return True, selected
    if any(result is None for result in results):
        return None, selected
    return False, selected


def _network_policy_analysis(
    evidence: EvidenceBundle, service: Service
) -> tuple[
    tuple[ObservedEvidence, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    policy_evidence = evidence.network_policy_evidence
    if policy_evidence is None:
        return ((), (), (), ("NetworkPolicy evidence was not collected.",))
    if policy_evidence.completeness_issues:
        return (
            (),
            (),
            (),
            (
                "NetworkPolicy evidence is incomplete, so it cannot support a "
                "policy conclusion.",
                *policy_evidence.completeness_issues,
            ),
        )
    pod_evidence = evidence.pod_evidence
    if pod_evidence is None or pod_evidence.completeness_issues:
        return (
            (),
            (),
            (),
            ("Complete Pod evidence is required for NetworkPolicy selection.",),
        )
    policies = policy_evidence.policies or ()
    required_keys = {
        key for policy in policies for key in _selector_keys(policy.pod_selector)
    }
    projected_keys = set(pod_evidence.projected_label_keys or ())
    if not required_keys.issubset(projected_keys):
        return (
            (),
            (),
            (),
            (
                "Pod label projection does not cover every NetworkPolicy target "
                "selector key.",
            ),
        )
    pods = pod_evidence.pods or ()
    service_pods = tuple(pod for pod in pods if _pod_matches_selector(pod, service))
    observation = ObservedEvidence(
        statement=(
            f"Complete NetworkPolicy snapshot contains {len(policies)} policies; "
            f"{len(service_pods)} observed Pods match the Service selector"
        ),
        source=evidence.source,
        source_collected_at=evidence.source_collected_at,
        collected_at=evidence.collected_at,
        resource=(
            f"NetworkPolicyList/{evidence.scope.namespace}"
            f"@{policy_evidence.resource_version}"
        ),
        transformations=(
            f"validated against {EVIDENCE_SCHEMA_VERSION}",
            "matched Kubernetes LabelSelectors and unioned applicable policy rules",
        ),
    )
    if not service_pods:
        return (
            (observation,),
            ("No observed Pod behind the Service was available for policy selection.",),
            (),
            (
                "NetworkPolicy effects cannot be evaluated without an observed "
                "Service-selected Pod.",
            ),
        )
    ingress_selected = sum(
        any(
            "Ingress" in policy.policy_types
            and _label_selector_matches(policy.pod_selector, pod.labels)
            for policy in policies
        )
        for pod in service_pods
    )
    egress_selected = sum(
        any(
            "Egress" in policy.policy_types
            and _label_selector_matches(policy.pod_selector, pod.labels)
            for policy in policies
        )
        for pod in service_pods
    )
    isolation = (
        f"NetworkPolicy selects {ingress_selected}/{len(service_pods)} Service Pods "
        f"for ingress isolation and {egress_selected}/{len(service_pods)} for "
        "egress isolation."
    )
    enforcement_limit = (
        "Policy objects describe intended isolation but do not prove that a network "
        "plugin enforces NetworkPolicy."
    )
    if evidence.traffic is None:
        possible = (
            ("NetworkPolicies may restrict traffic involving the Service Pods.",)
            if ingress_selected or egress_selected
            else ()
        )
        return (
            (observation,),
            (isolation,),
            possible,
            (
                "Source or destination, direction, protocol, and port context is "
                "required to evaluate a specific flow.",
                enforcement_limit,
            ),
        )
    traffic = evidence.traffic
    if traffic.peer.namespace is None and traffic.peer.ip is None:
        return (
            (observation,),
            (isolation,),
            ("NetworkPolicies may restrict the described traffic.",),
            (
                "Peer source or destination identity is missing, so a specific "
                "policy path cannot be evaluated.",
                enforcement_limit,
            ),
        )
    results = tuple(
        _pod_policy_result(pod, policies, traffic)[0] for pod in service_pods
    )
    allowed = sum(result is True for result in results)
    denied = sum(result is False for result in results)
    unknown = sum(result is None for result in results)
    description = f"{traffic.protocol}/{traffic.port} {traffic.direction} traffic"
    if denied == len(service_pods):
        return (
            (observation,),
            (
                isolation,
                f"The union of applicable NetworkPolicy rules does not allow the "
                f"described {description} for any of the {len(service_pods)} "
                "Service Pods.",
            ),
            ("NetworkPolicy enforcement may restrict the described traffic.",),
            (
                enforcement_limit,
                "A policy-spec deny is not proof that an observed connection was "
                "blocked by NetworkPolicy.",
            ),
        )
    if unknown:
        return (
            (observation,),
            (isolation,),
            ("NetworkPolicies may restrict the described traffic.",),
            (
                f"Policy evaluation is unresolved for {unknown} Service Pods; named "
                "ports or missing peer labels may require additional evidence.",
                enforcement_limit,
            ),
        )
    return (
        (observation,),
        (
            isolation,
            f"The union of applicable NetworkPolicy rules allows the described "
            f"{description} for {allowed}/{len(service_pods)} Service Pods.",
        ),
        (
            ("NetworkPolicies may restrict some Service Pods for this traffic.",)
            if denied
            else ()
        ),
        (enforcement_limit,),
    )


def _evaluate_service_no_ready_endpoints(
    evidence: EvidenceBundle,
) -> DiagnosticReport:
    """Evaluate SERVICE_NO_READY_ENDPOINTS from normalized evidence."""

    service = evidence.service
    pod_issues = (
        evidence.pod_evidence.collection_issues
        if evidence.pod_evidence is not None
        else ()
    )
    policy_issues = (
        evidence.network_policy_evidence.collection_issues
        if evidence.network_policy_evidence is not None
        else ()
    )
    collection_issues = (*evidence.collection_issues, *pod_issues, *policy_issues)
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
        if evidence.network_policy_evidence is None or service.selector is None:
            policy_observations: tuple[ObservedEvidence, ...] = ()
            policy_findings: tuple[str, ...] = ()
            policy_causes: tuple[str, ...] = ()
            policy_limitations: tuple[str, ...] = ()
        else:
            (
                policy_observations,
                policy_findings,
                policy_causes,
                policy_limitations,
            ) = _network_policy_analysis(evidence, service)
        return DiagnosticReport(
            rule_id=RULE_ID,
            outcome=Outcome.NO_FINDING,
            summary=f"{RULE_ID}: no finding for Service {service.identity}",
            target=evidence.scope,
            service=service,
            collection_issues=collection_issues,
            observed_evidence=(*observations, *policy_observations),
            derived_findings=(
                "At least one logical endpoint is explicitly ready.",
                *policy_findings,
            ),
            possible_causes=policy_causes,
            confirmed_causes=(),
            limitations=(
                *(
                    (f"{unknown_count} {unknown_label} unknown readiness.",)
                    if unknown_count
                    else ()
                ),
                *policy_limitations,
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
    if evidence.network_policy_evidence is None:
        policy_observations: tuple[ObservedEvidence, ...] = ()
        policy_findings: tuple[str, ...] = ()
        policy_causes: tuple[str, ...] = ()
        policy_limitations: tuple[str, ...] = ()
    else:
        (
            policy_observations,
            policy_findings,
            policy_causes,
            policy_limitations,
        ) = _network_policy_analysis(evidence, service)
    return DiagnosticReport(
        rule_id=RULE_ID,
        outcome=Outcome.FINDING,
        summary=f"{RULE_ID}: Service {service.identity} has no ready endpoints",
        target=evidence.scope,
        service=service,
        collection_issues=collection_issues,
        observed_evidence=(
            *observations,
            *pod_observations,
            *policy_observations,
        ),
        derived_findings=(
            "The complete associated EndpointSlice snapshot contains zero "
            "explicitly ready logical endpoints.",
            *pod_findings,
            *policy_findings,
        ),
        possible_causes=(*possible_causes, *policy_causes),
        confirmed_causes=confirmed_causes,
        limitations=(*limitations, *policy_limitations),
    )


def _flow_endpoint_matches_pod(endpoint: FlowEndpoint, pods: set[str]) -> bool:
    return bool(endpoint.namespace and endpoint.pod_name) and (
        f"{endpoint.namespace}/{endpoint.pod_name}" in pods
    )


@dataclass(frozen=True)
class _CorrelatedFlow:
    flow: Flow
    match_basis: tuple[str, ...]


def _match_service_endpoint(
    endpoint: FlowEndpoint,
    pod_ids: set[str],
    endpoint_ips: set[str],
) -> tuple[bool, tuple[str, ...], bool]:
    pod_identity_present = bool(endpoint.namespace and endpoint.pod_name)
    pod_match = pod_identity_present and _flow_endpoint_matches_pod(endpoint, pod_ids)
    ip_present = endpoint.ip is not None
    ip_match = ip_present and endpoint.ip in endpoint_ips
    if pod_identity_present and ip_present and pod_match != ip_match:
        return False, (), True
    basis = (
        *(("Pod identity",) if pod_match else ()),
        *(("EndpointSlice IP",) if ip_match else ()),
    )
    return bool(basis), basis, False


def _policy_correlation_state(
    evidence: EvidenceBundle, service: Service
) -> tuple[str | None, tuple[str, ...]]:
    policy_evidence = evidence.network_policy_evidence
    pod_evidence = evidence.pod_evidence
    traffic = evidence.traffic
    if (
        policy_evidence is None
        or policy_evidence.completeness_issues
        or pod_evidence is None
        or pod_evidence.completeness_issues
        or traffic is None
    ):
        return None, ()
    policies = policy_evidence.policies or ()
    required_keys = {
        key for policy in policies for key in _selector_keys(policy.pod_selector)
    }
    if not required_keys.issubset(set(pod_evidence.projected_label_keys or ())):
        return None, ()
    service_pods = tuple(
        pod for pod in (pod_evidence.pods or ()) if _pod_matches_selector(pod, service)
    )
    if not service_pods:
        return None, ()
    evaluated = tuple(
        _pod_policy_result(pod, policies, traffic) for pod in service_pods
    )
    results = tuple(result for result, _selected in evaluated)
    identities = tuple(
        sorted(
            {policy.identity for _result, selected in evaluated for policy in selected}
        )
    )
    if any(result is None for result in results):
        return "unknown", identities
    if all(result is False for result in results):
        return "restricted", identities
    if all(result is True for result in results):
        return "allowed", identities
    return "mixed", identities


def _readiness_cross_source_analysis(
    evidence: EvidenceBundle, report: DiagnosticReport
) -> tuple[tuple[ObservedEvidence, ...], tuple[str, ...], tuple[str, ...]]:
    service = evidence.service
    pod_evidence = evidence.pod_evidence
    if (
        report.outcome is not Outcome.NO_FINDING
        or service is None
        or service.selector is None
        or pod_evidence is None
        or pod_evidence.completeness_issues
    ):
        return (), (), ()
    matching = tuple(
        pod for pod in (pod_evidence.pods or ()) if _pod_matches_selector(pod, service)
    )
    if not matching or not all(pod.ready is False for pod in matching):
        return (), (), ()
    observation = ObservedEvidence(
        statement=(
            f"Complete Pod snapshot contains {len(matching)} Service-selected Pods; "
            "all explicitly report Ready=False"
        ),
        source=evidence.source,
        source_collected_at=evidence.source_collected_at,
        collected_at=evidence.collected_at,
        resource=f"PodList/{service.namespace}@{pod_evidence.resource_version}",
        transformations=(
            f"validated against {EVIDENCE_SCHEMA_VERSION}",
            "matched Pod labels against the observed Service selector",
        ),
    )
    finding = (
        f"EndpointSliceList/{service.identity}@"
        f"{evidence.endpoint_slice_resource_version} reports a ready endpoint, while "
        f"PodList/{service.namespace}@{pod_evidence.resource_version} reports every "
        "Service-selected Pod Ready=False."
    )
    return (
        (observation,),
        (finding,),
        (
            "EndpointSlice and Pod reads are not atomic; the disagreement cannot "
            "establish which readiness state is current.",
        ),
    )


def _flow_endpoint_identified(endpoint: FlowEndpoint) -> bool:
    return (
        endpoint.ip is not None
        or endpoint.identity is not None
        or bool(endpoint.namespace and endpoint.pod_name)
    )


def _normalized_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _hubble_analysis(
    evidence: EvidenceBundle,
) -> tuple[
    tuple[ObservedEvidence, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    flow_evidence = evidence.flow_evidence
    if flow_evidence is None:
        return (), (), (), (), ()
    limitations = list(flow_evidence.completeness_issues)
    service = evidence.service
    if service is None:
        limitations.append("An observed Service is required for Hubble correlation.")
        return (), (), (), (), tuple(limitations)
    if service.service_type == "ExternalName":
        return (), (), (), (), ()
    pod_evidence = evidence.pod_evidence
    pod_ids = (
        {
            pod.identity
            for pod in (pod_evidence.pods or ())
            if _pod_matches_selector(pod, service)
        }
        if service.selector is not None
        and pod_evidence is not None
        and not pod_evidence.completeness_issues
        else set()
    )
    endpoint_ips = (
        {
            endpoint.address
            for endpoint_slice in (evidence.endpoint_slices or ())
            for endpoint in endpoint_slice.endpoints
        }
        if not evidence.completeness_issues
        else set()
    )
    if not pod_ids and not endpoint_ips:
        limitations.append(
            "Complete Service-selected Pod identities or associated EndpointSlice "
            "IPs are required for Hubble correlation."
        )
        return (), (), (), (), tuple(limitations)

    window_start = (
        _normalized_datetime(flow_evidence.window_start)
        if flow_evidence.window_start
        else None
    )
    window_end = (
        _normalized_datetime(flow_evidence.window_end)
        if flow_evidence.window_end
        else None
    )
    metadata_time = _normalized_datetime(evidence.collected_at)
    window_overlaps = bool(
        window_start and window_end and window_start <= metadata_time <= window_end
    )
    correlated: list[_CorrelatedFlow] = []
    unmatched = 0
    ambiguous = 0
    out_of_window = 0
    for flow in flow_evidence.flows:
        flow_time = _normalized_datetime(flow.timestamp)
        if (window_start and flow_time < window_start) or (
            window_end and flow_time > window_end
        ):
            out_of_window += 1
            continue
        if not window_overlaps:
            continue
        traffic = evidence.traffic
        candidates = (
            (flow.destination,)
            if traffic is not None and traffic.direction == "ingress"
            else (
                (flow.source,)
                if traffic is not None and traffic.direction == "egress"
                else (flow.source, flow.destination)
            )
        )
        matches = tuple(
            _match_service_endpoint(endpoint, pod_ids, endpoint_ips)
            for endpoint in candidates
        )
        if any(match[2] for match in matches):
            ambiguous += 1
            continue
        matched_candidates = tuple(match for match in matches if match[0])
        if not matched_candidates:
            unmatched += 1
            continue
        basis = tuple(
            sorted({item for match in matched_candidates for item in match[1]})
        )
        relevant = True
        if traffic is not None:
            relevant = flow.direction == traffic.direction
            relevant = relevant and flow.protocol == traffic.protocol
            relevant = relevant and flow.destination_port == traffic.port
            peer = flow.source if traffic.direction == "ingress" else flow.destination
            if traffic.peer.namespace is not None:
                relevant = relevant and peer.namespace == traffic.peer.namespace
            if traffic.peer.ip is not None:
                relevant = relevant and peer.ip == traffic.peer.ip
        if relevant:
            correlated.append(_CorrelatedFlow(flow, basis))
        else:
            unmatched += 1
    matched = tuple(item.flow for item in correlated)
    forwarded = sum(flow.verdict in {"FORWARDED", "REDIRECTED"} for flow in matched)
    dropped = sum(flow.verdict == "DROPPED" for flow in matched)
    policy_drops = sum(
        flow.verdict == "DROPPED" and flow.policy_related is True for flow in matched
    )
    confirmable_policy_drops = sum(
        flow.verdict == "DROPPED"
        and flow.policy_related is True
        and flow.direction is not None
        and flow.protocol is not None
        and flow.destination_port is not None
        and _flow_endpoint_identified(flow.source)
        and _flow_endpoint_identified(flow.destination)
        for flow in matched
    )
    basis_counts = {
        basis: sum(basis in item.match_basis for item in correlated)
        for basis in ("Pod identity", "EndpointSlice IP")
    }
    observation = ObservedEvidence(
        statement=(
            f"Hubble observed {len(matched)} flows correlated to Service "
            f"{service.identity}: {forwarded} forwarded and {dropped} dropped"
        ),
        source="hubble",
        source_collected_at=flow_evidence.window_end or evidence.source_collected_at,
        collected_at=evidence.collected_at,
        resource=f"HubbleFlowWindow/{flow_evidence.window_start}..{flow_evidence.window_end}",
        transformations=(
            "projected metadata-only Hubble flow fields",
            (
                "correlated with "
                f"{basis_counts['Pod identity']} Pod-identity matches and "
                f"{basis_counts['EndpointSlice IP']} EndpointSlice-IP matches"
            ),
            "applied the optional direction, protocol, port, and peer context",
        ),
    )
    findings: list[str] = []
    possible: list[str] = []
    confirmed: list[str] = []
    if not window_overlaps:
        findings.append(
            "The Hubble window does not overlap the Kubernetes metadata snapshot, "
            "so its flows were not correlated."
        )
        limitations.append(
            "Non-overlapping flow and Kubernetes snapshots are stale for this "
            "bounded investigation."
        )
    elif not matched:
        findings.append("No matching Hubble flows were observed in the bounded window.")
        limitations.append(
            "Absence of observed flows does not prove that traffic did not occur."
        )
    if forwarded:
        findings.append(f"Hubble reported {forwarded} matching forwarded flows.")
        limitations.append("A forwarded flow does not prove application-level success.")
    if dropped:
        findings.append(f"Hubble reported {dropped} matching dropped flows.")
        possible.append(
            "Observed packet drops may explain the described communication failure."
        )
    if policy_drops:
        statement = (
            f"Hubble explicitly classified {policy_drops} matching drops as "
            "policy-related."
        )
        findings.append(statement)
        if not flow_evidence.completeness_issues and confirmable_policy_drops:
            confirmed.append(
                f"Hubble explicitly classified {confirmable_policy_drops} fully "
                "correlated matching drops as policy-related."
            )
        if flow_evidence.completeness_issues or confirmable_policy_drops < policy_drops:
            possible.append("Policy-related Hubble drops may explain the failure.")
            limitations.append(
                "A definitive Hubble policy-drop condition requires complete source, "
                "destination, direction, protocol, and port evidence."
            )
    if dropped > policy_drops:
        limitations.append(
            "A dropped verdict without explicit policy metadata is not attributed "
            "to NetworkPolicy."
        )
    if ambiguous:
        limitations.append(
            f"{ambiguous} flows had conflicting Pod-identity and EndpointSlice-IP "
            "associations and were not correlated."
        )
    if out_of_window:
        limitations.append(
            f"{out_of_window} flows fell outside the declared Hubble window and "
            "were excluded as stale."
        )
    if unmatched:
        limitations.append(
            f"{unmatched} collected flows did not match the available Service and "
            "traffic context."
        )

    endpoint_states = {
        endpoint.ready
        for endpoint_slice in (evidence.endpoint_slices or ())
        for endpoint in endpoint_slice.endpoints
    }
    ready_endpoints = True in endpoint_states
    if dropped and ready_endpoints:
        findings.append(
            f"EndpointSliceList/{service.identity}@"
            f"{evidence.endpoint_slice_resource_version} reports a ready endpoint, "
            "while the overlapping Hubble window contains relevant drops."
        )
        limitations.append(
            "Endpoint readiness does not establish that the observed network path "
            "or application request succeeded."
        )
    if forwarded and endpoint_states and True not in endpoint_states:
        findings.append(
            f"Hubble reports forwarded traffic correlated to {service.identity}, "
            "while its EndpointSlice snapshot contains zero ready endpoints."
        )
        limitations.append(
            "The forwarded flows and readiness snapshot may describe different "
            "packets or moments; neither resolves the other observation."
        )
    if pod_ids and pod_evidence is not None:
        matching_pods = tuple(
            pod for pod in (pod_evidence.pods or ()) if pod.identity in pod_ids
        )
        if (
            dropped
            and matching_pods
            and all(pod.ready is False for pod in matching_pods)
        ):
            findings.append(
                f"PodList/{service.namespace}@{pod_evidence.resource_version} reports "
                "all Service-selected Pods Ready=False, and Hubble independently "
                "reports relevant drops."
            )
            limitations.append(
                "Co-occurring Pod unready conditions and flow drops do not establish "
                "that either caused the other."
            )

    policy_state, policy_ids = _policy_correlation_state(evidence, service)
    policy_resource = (
        f"NetworkPolicyList/{service.namespace}@"
        f"{evidence.network_policy_evidence.resource_version}"
        if evidence.network_policy_evidence is not None
        else "NetworkPolicy evidence"
    )
    selected_description = (
        f" Selected policies: {', '.join(policy_ids)}." if policy_ids else ""
    )
    if policy_state == "restricted":
        if policy_drops:
            findings.append(
                f"{policy_resource} does not allow the described traffic for any "
                "Service-selected Pod, and Hubble independently reports explicit "
                f"policy-denial drops.{selected_description}"
            )
            limitations.append(
                "Agreement between policy specification and Hubble verdict metadata "
                "does not identify which policy or enforcement component caused a "
                "drop."
            )
        else:
            possible.append(
                "NetworkPolicy specifications may restrict the described traffic, "
                "but Hubble did not establish a corresponding policy drop."
            )
        if forwarded:
            findings.append(
                f"{policy_resource} does not allow the described traffic, while "
                "Hubble reports relevant forwarded flows."
            )
            limitations.append(
                "Policy specification and forwarded-flow evidence disagree; policy "
                "enforcement and snapshot timing remain unverified."
            )
    elif policy_state == "allowed" and policy_drops:
        findings.append(
            f"{policy_resource} allows the described traffic for all observed "
            "Service-selected Pods, while Hubble reports explicit policy-denial "
            f"drops.{selected_description}"
        )
        limitations.append(
            "The disagreement may reflect snapshot timing, another policy source, "
            "or enforcement state not represented by Kubernetes NetworkPolicy."
        )
    return (
        (observation,),
        tuple(findings),
        tuple(possible),
        tuple(confirmed),
        tuple(limitations),
    )


def evaluate_service_no_ready_endpoints(evidence: EvidenceBundle) -> DiagnosticReport:
    """Evaluate the primary rule and enrich it with optional Hubble evidence."""

    report = _evaluate_service_no_ready_endpoints(evidence)
    observations, findings, possible, confirmed, limitations = _hubble_analysis(
        evidence
    )
    readiness_observations, readiness_findings, readiness_limitations = (
        _readiness_cross_source_analysis(evidence, report)
    )
    issues = (
        evidence.flow_evidence.collection_issues
        if evidence.flow_evidence is not None
        else ()
    )
    summary = report.summary
    if any("matching dropped flows" in finding for finding in findings):
        summary = f"{summary}; correlated Hubble drops were observed"
    enriched = replace(
        report,
        summary=summary,
        collection_issues=(*report.collection_issues, *issues),
        observed_evidence=(
            *report.observed_evidence,
            *readiness_observations,
            *observations,
        ),
        derived_findings=(
            *report.derived_findings,
            *readiness_findings,
            *findings,
        ),
        possible_causes=(*report.possible_causes, *possible),
        confirmed_causes=(*report.confirmed_causes, *confirmed),
        limitations=(
            *report.limitations,
            *readiness_limitations,
            *limitations,
        ),
    )
    return explain_report(enriched, evidence)


def run_diagnostic(collector: EvidenceCollector) -> DiagnosticReport:
    """Run the collector, normalization, and rule pipeline."""

    return evaluate_service_no_ready_endpoints(normalize(collector.collect()))
