# KubeTrace

KubeTrace is a lightweight, evidence-based diagnostic tool for Kubernetes
networking investigations. It currently evaluates the deterministic
`SERVICE_NO_READY_ENDPOINTS` rule from either a JSON fixture or read-only
Kubernetes API evidence. When a selector-based Service has no ready endpoints,
optional Pod evidence can identify a bounded selector or readiness condition,
and NetworkPolicy evidence can show whether policy specifications may restrict
traffic involving the Service Pods. Optional Hubble flow evidence can correlate
forwarded and dropped traffic with those Pods over a bounded time window.

KubeTrace is not a general-purpose monitoring platform. It produces a bounded,
versioned diagnostic report that separates observations, derived findings,
possible causes, confirmed causes, and limitations.

## How it works

Both input modes use the same pipeline:

1. A collector obtains Service, EndpointSlice, Pod, and NetworkPolicy evidence
   when the investigation requires it, plus optional metadata-only Hubble flows.
2. The engine validates and normalizes the evidence into typed domain models.
3. A deterministic rule evaluates the normalized evidence.
4. The reporter writes versioned JSON to standard output and a terminal-safe
   one-line summary to standard error.

The Kubernetes collector uses only `read_namespaced_service`,
`list_namespaced_endpoint_slice`, `list_namespaced_pod`, and
`list_namespaced_network_policy`. It follows
pagination, requires a consistent non-empty resource version for each list, and
applies bounded page, object, timeout, and elapsed-time limits. Pod collection
is attempted only after complete EndpointSlice evidence establishes zero ready
endpoints for a selector-based Service or when NetworkPolicy selection must be
evaluated. Partial or failed evidence is never treated as proof of a cause.

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

Optional flow collection uses an existing `hubble` CLI installation and its
configured access to Hubble Relay. KubeTrace does not install or configure
Cilium, Hubble, credentials, or relay connectivity.

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

An optional traffic description enables evaluation of a specific policy path:

```powershell
python -m kubetrace kubernetes --namespace shop --service checkout `
  --direction ingress --protocol TCP --port 443 `
  --peer-namespace client --peer-namespace-label team=trusted `
  --peer-pod-label app=caller --peer-ip 192.0.2.10
```

Peer namespace and Pod labels are necessary when matching selectors use them.
The peer IP is necessary for `ipBlock` evaluation. Missing details produce an
explicitly limited result rather than an assumed allow or deny.

Add a bounded Hubble observation to the same investigation with:

```powershell
python -m kubetrace kubernetes --namespace shop --service checkout `
  --direction ingress --protocol TCP --port 443 --peer-ip 192.0.2.10 `
  --hubble --hubble-window-seconds 60 --hubble-max-flows 100
```

Use `--hubble-server` to select a relay endpoint and `--hubble-executable` when
the executable is not named `hubble`. The adapter invokes an argument array,
not a shell, and retains only flow metadata needed for correlation.

## Kubernetes permissions

The active identity needs `get` permission for Services and `list` permission
for EndpointSlices, Pods, and NetworkPolicies in the target namespace. A
namespace-scoped Role can express those permissions:

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
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
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

For a selector-based Service with a confirmed no-ready-endpoints finding, a
complete namespace-scoped Pod snapshot can additionally establish one of these
bounded conditions:

- no Pods were observed in the namespace;
- the Service selector matched none of the observed Pods; or
- every matching Pod explicitly reported `Ready=False`.

These are derived conditions that narrow the possible causes. Observing no Pods
or no selector matches is never reported as a confirmed root cause because the
evidence cannot establish workload intent. Only the all-matching-Pods-unready
condition is included in `confirmedCauses`, and it confirms the immediate
readiness condition rather than why readiness checks fail. A matching
`Ready=True` Pod contradicts the EndpointSlice snapshot, while missing or
unknown Pod readiness is insufficient to confirm an unready-Pod cause.
Incomplete Pod collection leaves `confirmedCauses` empty and records collection
issues and limitations; it does not erase a no-ready-endpoints finding already
established from complete EndpointSlice evidence.

### NetworkPolicy analysis

For observed Pods selected by the Service, KubeTrace identifies policies that
select each Pod for ingress or egress isolation. It implements Kubernetes label
selector semantics, direction-specific policy types, default-deny behavior,
the union of allow rules across applicable policies, protocol and numeric port
ranges, combined namespace and Pod selectors, and `ipBlock` exceptions.

With complete direction, peer, protocol, and port evidence, KubeTrace can state
whether the union of the observed policy specifications allows the described
traffic. A policy-spec deny is reported as a possible restriction, never as a
confirmed root cause. Policy objects alone do not prove that the cluster network
plugin enforces NetworkPolicy, and a selected Pod is not necessarily blocked.
Named policy ports remain unresolved because KubeTrace does not collect
container-port mappings.

### Hubble flow analysis

KubeTrace correlates a bounded Hubble window with the target Service using
complete Service-selected Pod identities and associated EndpointSlice IPs. When
both identifiers are present they must agree. Optional traffic direction,
protocol, destination port, peer namespace, and peer IP further constrain the
match. Flow and Kubernetes collection windows must overlap.

The report keeps each source's provenance and can describe combined conditions,
including ready endpoints with relevant drops, unready Pods with relevant
drops, or forwarded traffic observed alongside a no-ready-endpoints finding.
These are correlations between bounded observations, not causal conclusions.
The primary outcome continues to describe `SERVICE_NO_READY_ENDPOINTS`; flow
findings can therefore accompany either `finding` or `no_finding`.

Only a dropped verdict carrying explicit Hubble policy-denial metadata supports
a confirmed immediate policy-drop condition. When Kubernetes NetworkPolicy
evaluation independently suggests the same restriction, KubeTrace reports the
agreement but does not claim that a particular policy object caused the drop.
If policy specifications allow the described traffic, the disagreement is
reported with possible snapshot, alternate-policy-source, and enforcement
limitations. Generic drops remain unattributed, and matching policy selectors
alone are never treated as proof of a denial.

An empty flow window means that no matching flow was observed; it does not prove
that traffic did not occur. A forwarded verdict does not prove application-level
success. Unavailable, malformed, oversized, timed-out, or truncated Hubble
collection is reported as incomplete and cannot confirm a Hubble-derived cause.
Flows outside the declared window, non-overlapping source snapshots, missing
identities, and conflicting Pod-name/IP associations are excluded from strong
conclusions and recorded as limitations.

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
records, 1,000 Pods, 256 NetworkPolicies, 2,048 policy rules, 10,000 policy peer
and port entries, 1,000 flows, and 50 accumulated validation errors.

Kubernetes collection defaults to 100 objects per page. Each paginated list is
bounded to 16 pages; collection is additionally bounded to 256 EndpointSlices,
10,000 endpoint records, 1,000 Pods, 256 NetworkPolicies, 2,048 policy rules,
10,000 policy peer and port entries, and 15 elapsed seconds. Requests use a
three-second connect timeout and ten-second read timeout. Pod evidence retains
only identity, required selector label keys, and the Pod Ready condition.
NetworkPolicy projection omits annotations and unrelated metadata.
Hubble collection defaults to a 60-second window and 100 flows, permits at most
3,600 seconds and 1,000 flows, uses a ten-second command timeout, and accepts at
most 1,048,576 output bytes. Packet payloads are never retained.

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
- NetworkPolicy analysis describes policy specifications and cannot verify
  enforcement or prove that an observed connection was denied.
- Cilium policy CRDs and other provider-specific policy resources are not
  collected.
- Live-cluster compatibility is not covered by the automated test suite.
- Hubble integration currently supports newline-delimited JSON emitted by the
  Hubble CLI; direct Relay gRPC access and live compatibility testing are not
  implemented.
- Linux/eBPF tracing is not implemented.
- Service names use the portable RFC 1035 label rule; feature-gated relaxed
  Service-name validation is not modeled.
- The evidence and report schemas are versioned but may evolve before the first
  stable release.
