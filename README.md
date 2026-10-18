# kubetrace

Evidence-based Kubernetes network diagnostics using cluster metadata, Cilium/Hubble flows, and optional Linux/eBPF tracing.

KubeTrace currently implements one offline, fixture-driven diagnostic rule:
`SERVICE_NO_READY_ENDPOINTS`. Kubernetes, Cilium/Hubble, and Linux/eBPF live
collectors are planned evidence sources, not implemented features.

## Milestone 1

The CLI reads a synthetic Service and EndpointSlice collection, normalizes it,
evaluates the rule, writes a versioned JSON report to standard output, and writes
a one-line summary to standard error. It uses only the Python standard library
at runtime and does not require a cluster, containers, network access, or root.

Run it from PowerShell with the Python 3.11 baseline:

```powershell
$env:PYTHONPATH = "src"
python -m kubetrace fixtures/service-no-ready-endpoints.json
```

From WSL or another POSIX shell:

```sh
PYTHONPATH=src python3 -m kubetrace fixtures/service-no-ready-endpoints.json
```

Valid evidence returns exit status `0`, including findings, inconclusive results,
and rules that are not applicable. Invalid JSON or structurally invalid evidence
returns status `2` and a JSON validation-error report. Normal and validation-error
reports both use `kubetrace.report/v1`; validation errors set `service` to `null`,
populate `errors`, and leave the evidence and cause sections empty.

### Evidence-completeness contract

The engine can assert zero ready endpoints only when all of the following hold:

- collection status is `complete`;
- collection scope matches the Service namespace and name;
- the recorded EndpointSlice list request uses the Service namespace and exact
  `kubernetes.io/service-name=<service-name>` label selector;
- an `EndpointSliceList` is present with a non-empty `resourceVersion`;
- its pagination `continue` token is absent or empty; and
- every EndpointSlice has a unique identity and its namespace and
  `kubernetes.io/service-name` label associate it with the Service.

Request provenance is a collector attestation, not independently verified proof;
a fixture cannot prove the truth of its own assertions. A future live collector
must populate these fields from a successfully completed, consistently scoped API
list operation. Missing, partial, contradictory, or unassociated evidence
produces an inconclusive result. A truly empty list produces a finding only when
the entire attested contract is valid.

Endpoint readiness must be explicitly `true` to count as ready. If at least one
endpoint is explicitly ready, the rule produces no finding. If none is ready and
any readiness value is missing or `null`, the result is inconclusive. An empty
complete list or a list containing only explicitly unready endpoints produces a
finding. The rule applies to selectorless Services using the same endpoint
evidence, but does not treat the missing selector as a failure. It does not apply
to `ExternalName` Services.

This explicit-readiness policy is intentionally more conservative than native
Kubernetes EndpointSlice consumer semantics, which may interpret nil readiness
as ready. KubeTrace preserves missing or nil readiness as unknown for this rule.

Logical endpoint identity is `(addressType, canonical address)`. Identical
records are deduplicated, and conflicting readiness for one identity is
inconclusive. Milestone 1 diagnoses Service-level readiness and does not
distinguish otherwise identical addresses by EndpointSlice port or protocol.

### Input limits

To bound offline processing on the reference development machine, Milestone 1
accepts at most:

- 1,048,576 bytes per fixture;
- 256 EndpointSlices;
- 10,000 endpoint records; and
- 50 accumulated validation errors before validation stops.

These are fixed safety limits for the fixture milestone, not Kubernetes or
universal deployment limits.

### Diagnostic outcomes

- `finding`: complete evidence establishes zero explicitly ready endpoints.
- `no_finding`: at least one associated endpoint is explicitly ready.
- `inconclusive`: available evidence cannot establish either result.
- `not_applicable`: the Service type is outside this rule.
- `validation_error`: input is malformed or violates the fixture schema.

Reports keep observed evidence, derived findings, possible causes, and confirmed
causes separate. This rule observes a condition; it does not confirm why the
condition exists and emits no numeric confidence score.

## Development checks

Pytest and Ruff are development dependencies declared in `pyproject.toml`; they
are not runtime dependencies. With those tools available:

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

## Current limitations

- Only JSON fixtures using the source-neutral `kubetrace.evidence/v1` envelope
  are supported.
- Only `SERVICE_NO_READY_ENDPOINTS` is implemented.
- Live Kubernetes, Cilium/Hubble, and Linux/eBPF collection is not implemented.
- Service names use the portable RFC-1035 label rule; feature-gated relaxed
  Service-name validation is not modeled.
- The fixture schema and report schema are versioned but may evolve before the
  first stable release.
