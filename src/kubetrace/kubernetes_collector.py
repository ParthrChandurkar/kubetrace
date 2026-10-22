"""Read-only Kubernetes Service and EndpointSlice evidence collection."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Protocol

from kubetrace.engine import (
    MAX_ENDPOINT_SLICES,
    MAX_ENDPOINTS,
    MAX_PODS,
    SERVICE_NAME_LABEL,
    SUPPORTED_ADDRESS_TYPES,
    SUPPORTED_SERVICE_TYPES,
)
from kubetrace.models import EVIDENCE_SCHEMA_VERSION

MAX_COLLECTION_PAGES = 16
MAX_COLLECTION_ELAPSED_SECONDS = 15.0


class CoreApiClient(Protocol):
    def read_namespaced_service(self, **kwargs: Any) -> Any:
        """Read one namespaced Service."""

    def list_namespaced_pod(self, **kwargs: Any) -> Any:
        """List one page of namespaced Pods."""


class DiscoveryApiClient(Protocol):
    def list_namespaced_endpoint_slice(self, **kwargs: Any) -> Any:
        """List one page of namespaced EndpointSlices."""


@dataclass(frozen=True)
class CollectionBudgets:
    """Hard bounds for one Kubernetes metadata collection."""

    max_pages: int = MAX_COLLECTION_PAGES
    max_endpoint_slices: int = MAX_ENDPOINT_SLICES
    max_endpoints: int = MAX_ENDPOINTS
    max_pods: int = MAX_PODS
    max_elapsed_seconds: float = MAX_COLLECTION_ELAPSED_SECONDS

    def __post_init__(self) -> None:
        if not 1 <= self.max_pages <= MAX_COLLECTION_PAGES:
            raise ValueError(f"max_pages must be between 1 and {MAX_COLLECTION_PAGES}")
        if not 0 <= self.max_endpoint_slices <= MAX_ENDPOINT_SLICES:
            raise ValueError(
                f"max_endpoint_slices must be between 0 and {MAX_ENDPOINT_SLICES}"
            )
        if not 0 <= self.max_endpoints <= MAX_ENDPOINTS:
            raise ValueError(f"max_endpoints must be between 0 and {MAX_ENDPOINTS}")
        if not 0 <= self.max_pods <= MAX_PODS:
            raise ValueError(f"max_pods must be between 0 and {MAX_PODS}")
        if not 0 < self.max_elapsed_seconds <= MAX_COLLECTION_ELAPSED_SECONDS:
            raise ValueError(
                "max_elapsed_seconds must be between 0 and "
                f"{MAX_COLLECTION_ELAPSED_SECONDS}"
            )


@dataclass(frozen=True)
class _Issue:
    operation: str
    code: str
    message: str
    status: int | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "code": self.code,
            "message": self.message,
            "status": self.status,
        }


class _MalformedResponse(ValueError):
    pass


class KubernetesCollector:
    """Collect minimal Service, EndpointSlice, and Pod evidence."""

    def __init__(
        self,
        core_api: CoreApiClient,
        discovery_api: DiscoveryApiClient,
        namespace: str,
        service_name: str,
        clock: Callable[[], datetime],
        *,
        page_size: int = 100,
        request_timeout: float | tuple[float, float] = (3.0, 10.0),
        budgets: CollectionBudgets | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1 <= page_size <= MAX_ENDPOINT_SLICES:
            raise ValueError(f"page_size must be between 1 and {MAX_ENDPOINT_SLICES}")
        self.core_api = core_api
        self.discovery_api = discovery_api
        self.namespace = namespace
        self.service_name = service_name
        self.clock = clock
        self.page_size = page_size
        self.request_timeout = request_timeout
        self.budgets = budgets or CollectionBudgets()
        self.monotonic_clock = monotonic_clock

    def collect(self) -> Mapping[str, Any]:
        """Return a bounded source-neutral evidence envelope."""

        started = self.monotonic_clock()
        collected_at = self._collected_at()
        try:
            self._check_elapsed(started, "read_service")
            response = self.core_api.read_namespaced_service(
                name=self.service_name,
                namespace=self.namespace,
                _request_timeout=self.request_timeout,
            )
            self._check_elapsed(started, "read_service")
            service = _project_service(response)
        except Exception as error:
            issue = self._issue_from_exception("read_service", error)
            return self._envelope(collected_at, "incomplete", None, None, (issue,))

        if service["spec"]["type"] == "ExternalName":
            return self._envelope(collected_at, "complete", service, None, ())

        selector = f"{SERVICE_NAME_LABEL}={self.service_name}"
        items: list[dict[str, Any]] = []
        resource_version: str | None = None
        continuation: str | None = None
        seen_tokens: set[str] = set()
        page_count = 0
        endpoint_count = 0

        while True:
            if page_count >= self.budgets.max_pages:
                issue = _Issue(
                    "list_endpoint_slices",
                    "page_limit",
                    "EndpointSlice collection exceeded its page limit.",
                )
                return self._envelope(
                    collected_at,
                    "incomplete",
                    service,
                    self._list_payload(items, resource_version, continuation),
                    (issue,),
                    selector,
                )
            try:
                self._check_elapsed(started, "list_endpoint_slices")
                arguments: dict[str, Any] = {
                    "namespace": self.namespace,
                    "label_selector": selector,
                    "limit": self.page_size,
                    "_request_timeout": self.request_timeout,
                }
                if continuation:
                    arguments["_continue"] = continuation
                response = self.discovery_api.list_namespaced_endpoint_slice(
                    **arguments
                )
                self._check_elapsed(started, "list_endpoint_slices")
                page = _project_endpoint_slice_page(response)
            except Exception as error:
                issue = self._issue_from_exception("list_endpoint_slices", error)
                return self._envelope(
                    collected_at,
                    "incomplete",
                    service,
                    self._list_payload(items, resource_version, continuation),
                    (issue,),
                    selector,
                )

            page_count += 1
            page_resource_version = page["metadata"]["resourceVersion"]
            next_token = page["metadata"]["continue"]
            page_items = page["items"]

            if not page_resource_version:
                issue = _Issue(
                    "list_endpoint_slices",
                    "missing_resource_version",
                    "EndpointSlice list page had no resource version.",
                )
                return self._incomplete_page(
                    collected_at,
                    service,
                    items,
                    resource_version,
                    next_token,
                    issue,
                    selector,
                )
            if resource_version is None:
                resource_version = page_resource_version
            elif page_resource_version != resource_version:
                issue = _Issue(
                    "list_endpoint_slices",
                    "resource_version_mismatch",
                    "EndpointSlice list pages did not share one resource version.",
                )
                return self._incomplete_page(
                    collected_at,
                    service,
                    items,
                    resource_version,
                    next_token,
                    issue,
                    selector,
                )

            if len(items) + len(page_items) > self.budgets.max_endpoint_slices:
                issue = _Issue(
                    "list_endpoint_slices",
                    "slice_limit",
                    "EndpointSlice collection exceeded its slice limit.",
                )
                return self._incomplete_page(
                    collected_at,
                    service,
                    items,
                    resource_version,
                    next_token,
                    issue,
                    selector,
                )
            page_endpoint_count = sum(len(item["endpoints"]) for item in page_items)
            if endpoint_count + page_endpoint_count > self.budgets.max_endpoints:
                issue = _Issue(
                    "list_endpoint_slices",
                    "endpoint_limit",
                    "EndpointSlice collection exceeded its endpoint limit.",
                )
                return self._incomplete_page(
                    collected_at,
                    service,
                    items,
                    resource_version,
                    next_token,
                    issue,
                    selector,
                )

            items.extend(page_items)
            endpoint_count += page_endpoint_count
            if not next_token:
                pod_collection: dict[str, Any] | None = None
                pod_list: dict[str, Any] | None = None
                service_selector = service["spec"]["selector"]
                if _supports_pod_collection(
                    self.namespace,
                    self.service_name,
                    service,
                    items,
                ):
                    pod_collection, pod_list = self._collect_pods(
                        started, service_selector
                    )
                return self._envelope(
                    collected_at,
                    "complete",
                    service,
                    self._list_payload(items, resource_version, ""),
                    (),
                    selector,
                    pod_collection=pod_collection,
                    pod_list=pod_list,
                )
            if next_token in seen_tokens:
                issue = _Issue(
                    "list_endpoint_slices",
                    "repeated_continue_token",
                    "EndpointSlice pagination repeated a continuation token.",
                )
                return self._incomplete_page(
                    collected_at,
                    service,
                    items,
                    resource_version,
                    next_token,
                    issue,
                    selector,
                )
            seen_tokens.add(next_token)
            continuation = next_token

    def _collect_pods(
        self, started: float, selector: Mapping[str, str]
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        items: list[dict[str, Any]] = []
        resource_version: str | None = None
        continuation: str | None = None
        seen_tokens: set[str] = set()
        page_count = 0

        while True:
            if page_count >= self.budgets.max_pages:
                issue = _Issue(
                    "list_pods",
                    "page_limit",
                    "Pod collection exceeded its page limit.",
                )
                return (
                    self._pod_collection_payload("incomplete", (issue,)),
                    self._pod_list_payload(items, resource_version, continuation),
                )
            try:
                self._check_elapsed(started, "list_pods")
                arguments: dict[str, Any] = {
                    "namespace": self.namespace,
                    "label_selector": "",
                    "limit": self.page_size,
                    "_request_timeout": self.request_timeout,
                }
                if continuation:
                    arguments["_continue"] = continuation
                response = self.core_api.list_namespaced_pod(**arguments)
                self._check_elapsed(started, "list_pods")
                page = _project_pod_page(response, selector)
            except Exception as error:
                issue = self._issue_from_exception("list_pods", error)
                return (
                    self._pod_collection_payload("incomplete", (issue,)),
                    self._pod_list_payload(items, resource_version, continuation),
                )

            page_count += 1
            page_resource_version = page["metadata"]["resourceVersion"]
            next_token = page["metadata"]["continue"]
            page_items = page["items"]

            if not page_resource_version:
                issue = _Issue(
                    "list_pods",
                    "missing_resource_version",
                    "Pod list page had no resource version.",
                )
                return (
                    self._pod_collection_payload("incomplete", (issue,)),
                    self._pod_list_payload(items, resource_version, next_token),
                )
            if resource_version is None:
                resource_version = page_resource_version
            elif page_resource_version != resource_version:
                issue = _Issue(
                    "list_pods",
                    "resource_version_mismatch",
                    "Pod list pages did not share one resource version.",
                )
                return (
                    self._pod_collection_payload("incomplete", (issue,)),
                    self._pod_list_payload(items, resource_version, next_token),
                )
            if len(items) + len(page_items) > self.budgets.max_pods:
                issue = _Issue(
                    "list_pods",
                    "pod_limit",
                    "Pod collection exceeded its Pod limit.",
                )
                return (
                    self._pod_collection_payload("incomplete", (issue,)),
                    self._pod_list_payload(items, resource_version, next_token),
                )

            items.extend(page_items)
            if not next_token:
                return (
                    self._pod_collection_payload("complete", ()),
                    self._pod_list_payload(items, resource_version, ""),
                )
            if next_token in seen_tokens:
                issue = _Issue(
                    "list_pods",
                    "repeated_continue_token",
                    "Pod pagination repeated a continuation token.",
                )
                return (
                    self._pod_collection_payload("incomplete", (issue,)),
                    self._pod_list_payload(items, resource_version, next_token),
                )
            seen_tokens.add(next_token)
            continuation = next_token

    def _pod_collection_payload(
        self, status: str, issues: tuple[_Issue, ...]
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": status,
            "request": {
                "namespace": self.namespace,
                "labelSelector": "",
            },
        }
        if issues:
            payload["issues"] = [issue.payload() for issue in issues]
        return payload

    def _pod_list_payload(
        self,
        items: Sequence[dict[str, Any]],
        resource_version: str | None,
        continuation: str | None,
    ) -> dict[str, Any] | None:
        if resource_version is None and not items:
            return None
        return {
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {
                "resourceVersion": resource_version,
                "continue": continuation,
            },
            "items": sorted(
                items,
                key=lambda item: (
                    item["metadata"]["namespace"],
                    item["metadata"]["name"],
                ),
            ),
        }

    def _collected_at(self) -> str:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    def _check_elapsed(self, started: float, operation: str) -> None:
        if self.monotonic_clock() - started > self.budgets.max_elapsed_seconds:
            raise TimeoutError(f"{operation} exceeded the collection time budget")

    def _issue_from_exception(self, operation: str, error: Exception) -> _Issue:
        if isinstance(error, _MalformedResponse):
            return _Issue(
                operation,
                "invalid_response",
                "Kubernetes API returned a malformed response.",
            )
        status = getattr(error, "status", None)
        if (
            not isinstance(status, int)
            or isinstance(status, bool)
            or not 100 <= status <= 599
        ):
            status = None
        if status == 401:
            return _Issue(
                operation,
                "unauthorized",
                "Kubernetes API authentication was rejected.",
                status,
            )
        if status == 403:
            return _Issue(
                operation,
                "forbidden",
                "Kubernetes API authorization was denied.",
                status,
            )
        if status == 404:
            return _Issue(
                operation,
                "not_found",
                "The requested Kubernetes resource was not found.",
                status,
            )
        if status == 410:
            return _Issue(
                operation,
                "pagination_expired",
                "The Kubernetes pagination snapshot expired.",
                status,
            )
        if isinstance(error, TimeoutError) or "timeout" in type(error).__name__.lower():
            return _Issue(
                operation,
                "timeout",
                "Kubernetes API collection timed out.",
                status,
            )
        if status is not None:
            return _Issue(
                operation,
                "api_error",
                "Kubernetes API collection failed.",
                status,
            )
        return _Issue(
            operation,
            "transport_error",
            "Kubernetes API transport failed.",
        )

    def _incomplete_page(
        self,
        collected_at: str,
        service: dict[str, Any],
        items: list[dict[str, Any]],
        resource_version: str | None,
        continuation: str | None,
        issue: _Issue,
        selector: str,
    ) -> Mapping[str, Any]:
        return self._envelope(
            collected_at,
            "incomplete",
            service,
            self._list_payload(items, resource_version, continuation),
            (issue,),
            selector,
        )

    def _list_payload(
        self,
        items: Sequence[dict[str, Any]],
        resource_version: str | None,
        continuation: str | None,
    ) -> dict[str, Any] | None:
        if resource_version is None and not items:
            return None
        return {
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSliceList",
            "metadata": {
                "resourceVersion": resource_version,
                "continue": continuation,
            },
            "items": sorted(
                items,
                key=lambda item: (
                    item["metadata"]["namespace"],
                    item["metadata"]["name"],
                ),
            ),
        }

    def _envelope(
        self,
        collected_at: str,
        status: str,
        service: dict[str, Any] | None,
        endpoint_slice_list: dict[str, Any] | None,
        issues: tuple[_Issue, ...],
        selector: str | None = None,
        *,
        pod_collection: dict[str, Any] | None = None,
        pod_list: dict[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        collection: dict[str, Any] = {
            "source": "kubernetes-api",
            "collectedAt": collected_at,
            "status": status,
            "scope": {
                "namespace": self.namespace,
                "serviceName": self.service_name,
            },
        }
        if selector is not None:
            collection["endpointSliceListRequest"] = {
                "namespace": self.namespace,
                "labelSelector": selector,
            }
        if issues:
            collection["issues"] = [issue.payload() for issue in issues]
        if pod_collection is not None:
            collection["podListCollection"] = pod_collection

        envelope: dict[str, Any] = {
            "schemaVersion": EVIDENCE_SCHEMA_VERSION,
            "collection": collection,
        }
        if service is not None:
            envelope["service"] = service
        if endpoint_slice_list is not None:
            envelope["endpointSliceList"] = endpoint_slice_list
        if pod_list is not None:
            envelope["podList"] = pod_list
        return envelope


def _supports_pod_collection(
    namespace: str,
    service_name: str,
    service: Mapping[str, Any],
    endpoint_slices: Sequence[dict[str, Any]],
) -> bool:
    if service.get("apiVersion") != "v1" or service.get("kind") != "Service":
        return False
    metadata = service["metadata"]
    spec = service["spec"]
    if (
        metadata["namespace"] != namespace
        or metadata["name"] != service_name
        or spec["type"] not in SUPPORTED_SERVICE_TYPES - {"ExternalName"}
    ):
        return False
    selector = spec["selector"]
    if not selector:
        return False

    identities: set[tuple[str, str]] = set()
    for endpoint_slice in endpoint_slices:
        slice_metadata = endpoint_slice["metadata"]
        identity = (slice_metadata["namespace"], slice_metadata["name"])
        address_type = endpoint_slice["addressType"]
        if (
            endpoint_slice["apiVersion"] != "discovery.k8s.io/v1"
            or endpoint_slice["kind"] != "EndpointSlice"
            or address_type not in SUPPORTED_ADDRESS_TYPES
            or slice_metadata["namespace"] != namespace
            or slice_metadata["labels"].get(SERVICE_NAME_LABEL) != service_name
            or identity in identities
        ):
            return False
        identities.add(identity)

        expected_address = IPv4Address if address_type == "IPv4" else IPv6Address
        for endpoint in endpoint_slice["endpoints"]:
            if endpoint["conditions"]["ready"] is not False:
                return False
            for address in endpoint["addresses"]:
                try:
                    parsed = ip_address(address)
                except ValueError:
                    return False
                if not isinstance(parsed, expected_address):
                    return False
    return True


def _required_attribute(value: Any, name: str) -> Any:
    try:
        result = getattr(value, name)
    except (AttributeError, TypeError) as error:
        raise _MalformedResponse from error
    if result is None:
        raise _MalformedResponse
    return result


def _required_string_attribute(value: Any, name: str) -> str:
    result = _required_attribute(value, name)
    if not isinstance(result, str) or not result:
        raise _MalformedResponse
    return result


def _project_service(value: Any) -> dict[str, Any]:
    metadata = _required_attribute(value, "metadata")
    spec = _required_attribute(value, "spec")
    selector = getattr(spec, "selector", None)
    if selector is not None and (
        not isinstance(selector, Mapping)
        or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in selector.items()
        )
    ):
        raise _MalformedResponse
    projected_spec: dict[str, Any] = {
        "type": _required_string_attribute(spec, "type"),
        "selector": dict(selector) if selector is not None else None,
    }
    external_name = getattr(spec, "external_name", None)
    if external_name is not None and not isinstance(external_name, str):
        raise _MalformedResponse
    if external_name is not None:
        projected_spec["externalName"] = external_name
    return {
        "apiVersion": _required_string_attribute(value, "api_version"),
        "kind": _required_string_attribute(value, "kind"),
        "metadata": {
            "namespace": _required_string_attribute(metadata, "namespace"),
            "name": _required_string_attribute(metadata, "name"),
            "uid": _required_string_attribute(metadata, "uid"),
        },
        "spec": projected_spec,
    }


def _project_endpoint_slice_page(value: Any) -> dict[str, Any]:
    if (
        _required_string_attribute(value, "api_version") != "discovery.k8s.io/v1"
        or _required_string_attribute(value, "kind") != "EndpointSliceList"
    ):
        raise _MalformedResponse
    metadata = _required_attribute(value, "metadata")
    page_items = _required_attribute(value, "items")
    if not isinstance(page_items, list):
        raise _MalformedResponse
    resource_version = _required_attribute(metadata, "resource_version")
    continuation = getattr(metadata, "_continue", None)
    if not isinstance(resource_version, str) or (
        continuation is not None and not isinstance(continuation, str)
    ):
        raise _MalformedResponse
    return {
        "metadata": {
            "resourceVersion": resource_version,
            "continue": continuation or "",
        },
        "items": [_project_endpoint_slice(item) for item in page_items],
    }


def _project_endpoint_slice(value: Any) -> dict[str, Any]:
    metadata = _required_attribute(value, "metadata")
    endpoints = _required_attribute(value, "endpoints")
    if not isinstance(endpoints, list):
        raise _MalformedResponse
    labels = _required_attribute(metadata, "labels")
    if not isinstance(labels, Mapping):
        raise _MalformedResponse
    service_name = labels.get(SERVICE_NAME_LABEL)
    if service_name is not None and not isinstance(service_name, str):
        raise _MalformedResponse
    projected = {
        "apiVersion": _required_string_attribute(value, "api_version"),
        "kind": _required_string_attribute(value, "kind"),
        "addressType": _required_string_attribute(value, "address_type"),
        "metadata": {
            "namespace": _required_string_attribute(metadata, "namespace"),
            "name": _required_string_attribute(metadata, "name"),
            "labels": {
                SERVICE_NAME_LABEL: service_name,
            },
        },
        "endpoints": [_project_endpoint(endpoint) for endpoint in endpoints],
    }
    projected["endpoints"].sort(
        key=lambda endpoint: (
            tuple(endpoint["addresses"]),
            repr(endpoint["conditions"]["ready"]),
        )
    )
    return projected


def _project_endpoint(value: Any) -> dict[str, Any]:
    addresses = _required_attribute(value, "addresses")
    if (
        not isinstance(addresses, list)
        or not addresses
        or not all(isinstance(address, str) for address in addresses)
    ):
        raise _MalformedResponse
    conditions = getattr(value, "conditions", None)
    ready = None if conditions is None else getattr(conditions, "ready", None)
    if ready is not None and not isinstance(ready, bool):
        raise _MalformedResponse
    return {
        "addresses": sorted(addresses),
        "conditions": {"ready": ready},
    }


def _project_pod_page(value: Any, selector: Mapping[str, str]) -> dict[str, Any]:
    if (
        _required_string_attribute(value, "api_version") != "v1"
        or _required_string_attribute(value, "kind") != "PodList"
    ):
        raise _MalformedResponse
    metadata = _required_attribute(value, "metadata")
    page_items = _required_attribute(value, "items")
    if not isinstance(page_items, list):
        raise _MalformedResponse
    resource_version = _required_attribute(metadata, "resource_version")
    continuation = getattr(metadata, "_continue", None)
    if not isinstance(resource_version, str) or (
        continuation is not None and not isinstance(continuation, str)
    ):
        raise _MalformedResponse
    return {
        "metadata": {
            "resourceVersion": resource_version,
            "continue": continuation or "",
        },
        "items": [_project_pod(item, selector) for item in page_items],
    }


def _project_pod(value: Any, selector: Mapping[str, str]) -> dict[str, Any]:
    metadata = _required_attribute(value, "metadata")
    labels_value = getattr(metadata, "labels", None)
    if labels_value is None:
        labels: Mapping[str, Any] = {}
    elif isinstance(labels_value, Mapping):
        labels = labels_value
    else:
        raise _MalformedResponse

    projected_labels: dict[str, str] = {}
    for key in selector:
        label_value = labels.get(key)
        if label_value is not None:
            if not isinstance(label_value, str):
                raise _MalformedResponse
            projected_labels[key] = label_value

    status = getattr(value, "status", None)
    conditions = None if status is None else getattr(status, "conditions", None)
    if conditions is None:
        ready = None
    else:
        if not isinstance(conditions, list):
            raise _MalformedResponse
        ready_values: list[bool | None] = []
        for condition in conditions:
            condition_type = _required_string_attribute(condition, "type")
            if condition_type != "Ready":
                continue
            condition_status = _required_string_attribute(condition, "status")
            try:
                ready_values.append(
                    {"True": True, "False": False, "Unknown": None}[condition_status]
                )
            except KeyError as error:
                raise _MalformedResponse from error
        if len(ready_values) > 1:
            raise _MalformedResponse
        ready = ready_values[0] if ready_values else None

    return {
        "apiVersion": _required_string_attribute(value, "api_version"),
        "kind": _required_string_attribute(value, "kind"),
        "metadata": {
            "namespace": _required_string_attribute(metadata, "namespace"),
            "name": _required_string_attribute(metadata, "name"),
            "uid": _required_string_attribute(metadata, "uid"),
            "labels": projected_labels,
        },
        "status": {"ready": ready},
    }
