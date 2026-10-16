# AGENTS.md

## Project purpose

KubeTrace is an open-source, Python-based diagnostic tool for investigating
Kubernetes network failures. Its core value is an evidence-based explanation
of a bounded incident: collect relevant cluster metadata and network-flow
observations, correlate them, test explicit diagnostic rules, and report both
supporting evidence and uncertainty.

KubeTrace is not a general-purpose monitoring, log aggregation, or observability
platform. Prometheus and Grafana may be optional supporting integrations, but
must not become required runtime components or the primary user experience.
Do not add AI/LLM diagnosis, a frontend, cloud deployment, or extra services
without a separately documented use case and design decision.

## Product and architecture boundaries

Keep the diagnostic engine modular and incremental. Prefer these logical
boundaries as the codebase develops:

- `domain`: stable typed models for investigation scope, Kubernetes resources,
  flow observations, trace events, evidence, hypotheses, and findings.
- `collectors`: read-only adapters for Kubernetes metadata, Cilium/Hubble flow
  data, and optional host-level Linux/eBPF observations.
- `normalization`: conversion of source-specific payloads into domain models,
  including timestamps, identities, endpoints, and provenance.
- `correlation`: deterministic joins across workload identity, IP, namespace,
  node, service, policy, port, protocol, and bounded time windows.
- `rules`: small, independently tested diagnostic rules that emit findings with
  evidence, confidence limits, and possible alternative explanations.
- `orchestration`: investigation lifecycle, capability detection, collection
  budgets, cancellation, and partial-result handling.
- `reporting`: machine-readable output first, with a concise terminal rendering;
  do not couple diagnostic logic to presentation.
- `integrations`: optional, isolated adapters such as Prometheus enrichment.

These are logical boundaries, not a requirement to create eight packages
immediately. Start with the simplest maintainable structure and introduce
abstractions only when actual implementations justify them.

Keep ports/interfaces between these areas narrow. Source adapters must not own
root-cause policy, and rules must not call infrastructure APIs directly. The
core engine must remain usable when optional eBPF tracing or integrations are
unavailable. Prefer a single-process CLI/library design until measurements show
that another service is necessary.

Fixture sources must implement the same collector contract and pass through the
same normalization, diagnostic-rule, and reporting pipeline intended for live
evidence collectors. Fixtures must not bypass those stages.

Build in stages:

1. Define domain models, investigation scope, fixture-based inputs, and report
   schemas.
2. Add read-only Kubernetes metadata collection and deterministic diagnostics.
3. Add Hubble flow ingestion and correlation behind a capability check.
4. Add optional Linux/eBPF tracing only after the target kernel, privileges,
   Cilium configuration, and WSL 2/Minikube topology have been validated.
5. Add optional supporting integrations only for a demonstrated evidence gap.

## Coding conventions

- Target Python 3.11 or newer, with Python 3.11.9 as the initial baseline. Do
  not assume other installed interpreter versions are project-tested.
- Use type annotations for public interfaces and domain models. Prefer explicit
  dataclasses or similarly transparent models over untyped dictionaries.
- Keep I/O at adapter boundaries and keep normalization, correlation, and rules
  deterministic and side-effect free where practical.
- Use dependency injection for cluster clients, clocks, command execution, and
  trace sources so tests do not require a live cluster or privileged host.
- Prefer small modules with one responsibility. Avoid global mutable state,
  hidden singleton clients, import-time network access, and import-time system
  checks.
- Use structured errors that preserve source, operation, and remediation
  context. Optional-source failure should yield an explicit partial result when
  safe, not fabricate evidence or erase the whole investigation.
- Use UTC internally and emit timezone-aware timestamps. Preserve source
  timestamps and record collection time separately.
- Attach provenance to every observation: source, collection method, resource
  identity, relevant time range, and transformations applied.
- Keep serialized output versioned and deterministic. Never make terminal text
  the only representation of a finding.
- Introduce dependencies only when they reduce meaningful implementation or
  correctness risk. Keep optional integrations behind extras or equivalent
  optional boundaries.
- Record material architectural choices in short ADRs when a `docs/adr/`
  directory is introduced.

## Diagnostic and evidence standards

- A finding must clearly distinguish observed evidence, derived findings,
  possible causes, and confirmed causes.
- Every asserted cause must cite the concrete evidence used and the rule or
  reasoning step that connects it to the conclusion.
- State missing inputs and viable alternative causes. Use `unknown` or
  `inconclusive` when evidence is insufficient.
- Never claim packet loss, policy denial, DNS failure, connectivity, kernel
  behavior, or root cause solely because a data source is absent or a command
  failed.
- Do not imply that correlation proves causation. Define diagnostic outcome and
  confidence vocabulary before using it in reports; labels must have a
  documented, testable meaning. Do not emit arbitrary numeric confidence scores.
- Preserve negative evidence carefully: "not observed during this bounded
  collection window" is not equivalent to "did not happen."
- Prefer terminology from the source system and include source identifiers so a
  user can independently verify a finding.
- Test each diagnostic rule against counterexamples and ambiguous cases, not
  only the expected positive fixture.

## Testing expectations

- Unit-test domain validation, normalization, correlation, and each diagnostic
  rule with small deterministic fixtures.
- Add contract tests for adapters using recorded or synthetic API payloads. The
  default unit test suite must not require containers, cluster infrastructure,
  network access, root, or eBPF support.
- Mark live-cluster and privileged eBPF tests as explicit integration tests and
  keep them opt-in. Document prerequisites, expected resource usage, and cleanup.
- Run cluster integration tests sequentially by default. Measure their resource
  use before setting hard limits.
- Cover degraded operation: missing CRDs, unavailable Hubble relay, insufficient
  RBAC, expired observations, clock skew, truncated streams, cancellation, and
  unsupported kernels.
- Use synthetic or sanitized fixtures. Tests must not contain real credentials,
  cluster certificates, tokens, private addresses tied to real environments, or
  sensitive packet payloads.
- For every bug fix, add the smallest regression test that fails before the fix.
- Before considering a change complete, run the relevant formatter, linter,
  static type checks, and tests once those tools are selected and documented.
  Do not invent commands before the project defines its toolchain.

## Security and privacy requirements

- Default to read-only Kubernetes access and least-privilege RBAC. Any broader
  permission must be justified, documented, and isolated.
- Treat kubeconfigs, bearer tokens, client certificates, environment variables,
  packet contents, DNS names, labels, annotations, and workload metadata as
  potentially sensitive.
- Never log or serialize secrets. Redact credential-like values and minimize the
  collection and retention of payload data and personally identifiable data.
- Do not execute shell text assembled from cluster-controlled values. Prefer
  library APIs and argument arrays; validate all identifiers passed to external
  tools.
- Bound collection duration, event count, memory use, API pagination, and retry
  behavior. Support cancellation and cleanly close streams and probes.
- eBPF code and loaders are privileged attack surfaces. Pin dependencies,
  validate program/kernel compatibility, minimize capabilities, and document
  verifier, privilege, and cleanup behavior before enabling them.
- Never modify cluster policy, workloads, Cilium configuration, host networking,
  kernel settings, or system configuration as part of diagnosis without an
  explicit, separately scoped user action.
- Avoid shipping raw collected evidence by default. Make exports explicit and
  document their sensitivity and retention implications.

## Development environment and resource constraints

- The supported development path should remain compatible with Windows using
  WSL 2 Ubuntu, Docker Desktop, and Minikube.
- Run Linux-specific tooling inside WSL 2 or the relevant Minikube node, not by
  assuming native Windows kernel facilities.
- Do not assume eBPF works merely because WSL 2, Docker Desktop, Minikube, or
  Cilium starts. Validate kernel configuration, BTF availability, required
  capabilities, mount visibility, Cilium mode, Hubble availability, and where
  packets are actually observable.
- Capability detection must report why an optional collector is unavailable and
  continue with supported evidence sources where possible.
- Keep the default local workflow lightweight: no mandatory Prometheus, Grafana,
  message broker, database, service mesh, or multi-service stack.
- Keep the default unit-test suite practical on the constrained reference
  machine, which has 7.3 GB of physical RAM and approximately 3.49 GiB allocated
  to Docker. These are local development constraints, not universal project
  limits.
- Use bounded, reproducible test scenarios. Avoid unbounded flow capture, high
  cardinality retention, busy loops, and large container images.
- Do not install dependencies, start containers or clusters, or change host,
  Docker, WSL, Minikube, Kubernetes, Cilium, or kernel configuration unless the
  current task explicitly authorizes it.

## Change discipline

- Inspect existing files, applicable nested `AGENTS.md` files, `git status`, and
  relevant diffs before and after changes.
- Keep changes narrowly related to the requested task and never discard
  unrelated user changes.
- Do not reset the worktree destructively, rewrite history, or force-push.
- Do not edit generated files by hand. Do not commit, push, publish, or release
  without explicit user authorization.
- Update documentation and tests when behavior or output contracts change.
- Label unvalidated platform assumptions and feature claims. Do not describe a
  collector, integration, diagnosis, or compatibility path as working until it
  has an appropriate automated or documented manual verification.
