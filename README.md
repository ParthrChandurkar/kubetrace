# KubeTrace

KubeTrace is a lightweight, evidence-based diagnostic tool for Kubernetes
networking investigations. It currently evaluates the deterministic
`SERVICE_NO_READY_ENDPOINTS` rule from either a JSON fixture or read-only
Kubernetes API evidence.

KubeTrace is not a general-purpose monitoring platform. It produces a bounded,
versioned diagnostic report that separates observations, derived findings,
possible causes, confirmed causes, and limitations.

## How it works

Both input modes use the same pipeline:

1. A collector obtains Service and EndpointSlice evidence.
2. The engine validates and normalizes the evidence into typed domain models.
3. A deterministic rule evaluates the normalized evidence.
4. The reporter writes versioned JSON to standard output and a terminal-safe
   one-line summary to standard error.

The Kubernetes collector uses only `read_namespaced_service` and
`list_namespaced_endpoint_slice`. It follows pagination, requires a consistent
non-empty resource version, and applies bounded page, slice, endpoint, timeout,
and elapsed-time limits. Partial or failed collection is reported as
inconclusive rather than treated as proof of a fault.

## Prerequisites and installation

KubeTrace targets Python 3.11 or newer, with Python 3.11.9 as the tested
baseline. Fixture mode has no runtime dependencies outside the Python standard
library.

From the repository root, install the optional Kubernetes client only when live
API collection is needed:

```powershell
python -m pip install ".[kubernetes]"
```

Installing the extra does not establish cluster reachability, credentials, or
RBAC permissions. KubeTrace loads the Kubernetes package and kubeconfig only
when Kubernetes mode is selected.

## Usage

When running from a source checkout in PowerShell:

```powershell
$env:PYTHONPATH = "src"
```

For WSL or another POSIX shell, use `PYTHONPATH=src` before the commands below.
An installed package also provides the `kubetrace` command.

### Fixture evidence

The original fixture invocation remains supported:

```powershell
python -m kubetrace fixtures/service-no-ready-endpoints.json
```

The explicit form is equivalent:

```powershell
python -m kubetrace fixture fixtures/service-no-ready-endpoints.json
```

### Kubernetes API evidence

Select one namespaced Service with required namespace and Service arguments:

```powershell
python -m kubetrace kubernetes --namespace shop --service checkout
```

By default, the Kubernetes client uses its normal kubeconfig location and
current context. A different file or context can be selected explicitly:

```powershell
python -m kubetrace kubernetes --namespace shop --service checkout `
  --kubeconfig C:\path\to\config --context minikube
```

KubeTrace does not persist kubeconfig changes. Configuration, authentication,
authorization, connectivity, and API collection failures are emitted as
sanitized collection issues; kubeconfig contents, credentials, response bodies,
and raw exception text are not included in reports.

## Kubernetes permissions

The active identity needs `get` permission for Services and `list` permission
for EndpointSlices in the target namespace. A namespace-scoped Role can express
those permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kubetrace-reader
  namespace: shop
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["list"]
```

Binding the Role to an identity is an administrator action and is not performed
by KubeTrace. The collector does not create, update, patch, or delete Kubernetes
resources.

## Evidence and diagnostic semantics

The engine can assert zero ready endpoints only when all of the following hold:

- collection status is `complete`;
- collection scope matches the Service namespace and name;
- the EndpointSlice list request uses the Service namespace and exact
  `kubernetes.io/service-name=<service-name>` label selector;
- an `EndpointSliceList` is present with a non-empty `resourceVersion`;
- pagination completed without a remaining continuation token; and
- every EndpointSlice has a unique identity and is associated with the Service.

Endpoint readiness must be explicitly `true` to count as ready. If at least one
endpoint is explicitly ready, the rule produces no finding. If none is ready and
any readiness value is missing or `null`, the result is inconclusive. An empty,
complete list or a list containing only explicitly unready endpoints produces a
finding. Duplicate logical endpoints are deduplicated; contradictory readiness
for one identity is inconclusive.

The rule applies to selectorless Services without treating the missing selector
as a failure. It is not applicable to `ExternalName` Services. The rule observes
endpoint readiness; it does not confirm why the condition exists.

Diagnostic outcomes are:

- `finding`: complete evidence establishes zero explicitly ready endpoints.
- `no_finding`: at least one associated endpoint is explicitly ready.
- `inconclusive`: available evidence cannot establish either result.
- `not_applicable`: the Service type is outside this rule.
- `validation_error`: input is malformed or violates the evidence schema.

Valid investigations return exit status `0`, including inconclusive and
not-applicable results. Invalid evidence and structurally invalid collected data
return status `2`. Command-line usage errors also return status `2`.

## Output

Normal and validation-error reports use `kubetrace.report/v2`. Reports include
the requested target separately from an observed Service, so a failed Service
read cannot be presented as observed evidence. Bounded, sanitized
`collectionIssues` describe operational failures. JSON key ordering and list
normalization make equivalent reports deterministic, apart from collection
timestamps obtained at runtime.

## Resource limits

Fixture input is limited to 1,048,576 bytes, 256 EndpointSlices, 10,000 endpoint
records, and 50 accumulated validation errors.

Kubernetes collection defaults to 100 slices per page and is bounded to 16
pages, 256 slices, 10,000 endpoint records, and 15 elapsed seconds. Requests use
a three-second connect timeout and ten-second read timeout.

## Development checks

Pytest and Ruff are optional development dependencies declared in
`pyproject.toml`. With them available:

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m compileall -q src tests
git diff --check
```

The unit tests use fixtures and fake Kubernetes clients. They do not require a
cluster, network access, Docker, Minikube, root, or eBPF support.

## Limitations

- Only `SERVICE_NO_READY_ENDPOINTS` is implemented.
- Live-cluster compatibility is not covered by the automated test suite.
- Cilium/Hubble flow collection and Linux/eBPF tracing are not implemented.
- Service names use the portable RFC 1035 label rule; feature-gated relaxed
  Service-name validation is not modeled.
- The evidence and report schemas are versioned but may evolve before the first
  stable release.
