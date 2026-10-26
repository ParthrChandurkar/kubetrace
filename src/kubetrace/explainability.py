"""Deterministic report explanations and evidence-conditional guidance."""

from __future__ import annotations

from dataclasses import replace

from kubetrace.models import (
    DiagnosticExplanation,
    DiagnosticReport,
    EvidenceBundle,
    Outcome,
)

_MISSING_MARKERS = (
    "cannot",
    "conflicting",
    "does not overlap",
    "incomplete",
    "is missing",
    "not collected",
    "required",
    "stale",
    "unknown",
    "unresolved",
    "unavailable",
)

_CONTRADICTION_MARKERS = (
    "conflicting",
    "disagree",
    "inconsistent",
    "not atomic",
    "does not overlap",
    "different packets or moments",
)


def _unique(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _established(report: DiagnosticReport) -> tuple[str, ...]:
    established: list[str] = []
    if report.outcome is Outcome.FINDING:
        established.append(
            "Complete EndpointSlice evidence establishes that the Service has zero "
            "explicitly ready logical endpoints."
        )
    elif report.outcome is Outcome.NO_FINDING:
        established.append(
            "At least one associated logical endpoint is explicitly ready, so the "
            "no-ready-endpoints rule does not produce a finding."
        )
    elif report.outcome is Outcome.NOT_APPLICABLE:
        established.append(
            "The endpoint-readiness rule does not apply to this ExternalName Service."
        )
    established.extend(report.confirmed_causes)
    return _unique(established)


def _missing_evidence(report: DiagnosticReport) -> tuple[str, ...]:
    missing = [
        limitation
        for limitation in report.limitations
        if any(marker in limitation.lower() for marker in _MISSING_MARKERS)
    ]
    missing.extend(
        f"{issue.operation}: {issue.message}" for issue in report.collection_issues
    )
    return _unique(missing)


def _does_not_establish(report: DiagnosticReport) -> tuple[str, ...]:
    limits = list(report.limitations)
    if report.possible_causes:
        limits.append(
            "Possible causes are hypotheses supported or suggested by the available "
            "evidence; they are not confirmed causes."
        )
    if len({item.source for item in report.observed_evidence}) > 1:
        limits.append(
            "Agreement or timing correlation between evidence sources does not by "
            "itself establish causation."
        )
    if report.outcome is Outcome.INCONCLUSIVE:
        limits.append(
            "The available evidence does not establish whether the Service has a "
            "ready endpoint."
        )
    return _unique(limits)


def _guidance(report: DiagnosticReport, evidence: EvidenceBundle) -> tuple[str, ...]:
    steps: list[str] = []
    service = evidence.service
    identity = (
        service.identity
        if service is not None
        else f"{evidence.scope.namespace}/{evidence.scope.service_name}"
    )
    findings = " ".join(report.derived_findings)
    limitations = " ".join(report.limitations).lower()
    confirmed = " ".join(report.confirmed_causes)

    if service is None:
        if any(
            issue.code in {"forbidden", "unauthorized"}
            for issue in report.collection_issues
        ):
            steps.append(
                "Verify that the active Kubernetes identity can get the target "
                "Service and list the required namespace-scoped resources."
            )
        else:
            steps.append(
                "Verify Kubernetes client configuration, authentication, and API "
                f"connectivity, then recollect Service {identity}."
            )
    elif report.outcome is Outcome.NOT_APPLICABLE:
        steps.append(
            f"Investigate DNS resolution and destination reachability for "
            f"ExternalName Service {identity}; EndpointSlice readiness is not used."
        )
    elif report.outcome is Outcome.FINDING:
        if service.selector is None:
            steps.append(
                f"Inspect the manually managed EndpointSlices for selectorless "
                f"Service {identity}, including addresses and readiness conditions."
            )
        else:
            steps.append(
                f"Inspect Pods selected by Service {identity} and compare their "
                "labels and Ready conditions with the associated EndpointSlices."
            )
    elif report.outcome is Outcome.NO_FINDING:
        steps.append(
            f"No endpoint-readiness correction is indicated for Service {identity}; "
            "continue with the other reported network evidence."
        )
    elif report.outcome is Outcome.INCONCLUSIVE:
        steps.append(
            f"Resolve the reported missing or inconsistent evidence and recollect "
            f"Service {identity} before drawing an endpoint-readiness conclusion."
        )

    if "matches none" in findings:
        steps.append(
            f"Compare the selector on Service {identity} with labels on the intended "
            "Pods and correct only the owning configuration after verification."
        )
    elif "contains no Pods" in findings:
        steps.append(
            f"Inspect the workload controllers expected to create Pods in namespace "
            f"{evidence.scope.namespace}."
        )
    if "Ready=False" in confirmed or "Ready=False" in findings:
        steps.append(
            "Inspect the matching Pods' Ready conditions, readiness probes, events, "
            "and container status to determine why readiness is failing."
        )

    policy_restriction = any(
        phrase in findings
        for phrase in (
            "does not allow the described",
            "NetworkPolicy selects",
            "policy-denial",
        )
    ) or any("NetworkPolicy" in cause for cause in report.possible_causes)
    if evidence.network_policy_evidence is not None and policy_restriction:
        direction = (
            evidence.traffic.direction if evidence.traffic is not None else "relevant"
        )
        steps.append(
            f"Inspect the applicable NetworkPolicy {direction} selectors, peers, "
            "protocols, and ports for the Service-selected Pods."
        )

    pod_evidence = evidence.pod_evidence
    if pod_evidence is not None and pod_evidence.completeness_issues:
        steps.append(
            "Resolve the reported Pod list access, pagination, or consistency "
            "issue and repeat the bounded Pod collection."
        )

    policy_evidence = evidence.network_policy_evidence
    if policy_evidence is not None and policy_evidence.completeness_issues:
        steps.append(
            "Resolve the reported NetworkPolicy list access, pagination, or "
            "consistency issue and repeat the bounded policy collection."
        )

    if "Hubble explicitly classified" in confirmed:
        steps.append(
            "Inspect the correlated Hubble drop reason, direction, identities, and "
            "ports, then verify the Cilium policy enforcement state for that path."
        )
    elif "matching dropped flows" in findings:
        steps.append(
            "Inspect the correlated Hubble drop reasons and flow identities; do not "
            "attribute generic drops to policy without explicit denial metadata."
        )

    flow_evidence = evidence.flow_evidence
    if flow_evidence is not None and flow_evidence.completeness_issues:
        steps.append(
            "Verify Hubble CLI or Relay availability and repeat the bounded flow "
            "collection after resolving its reported completeness issues."
        )

    if any(marker in limitations for marker in _CONTRADICTION_MARKERS):
        steps.append(
            "Compare the conflicting source resource versions and timestamps, then "
            "recollect the sources in a tighter window before choosing a cause."
        )
    return _unique(steps)


def explain_report(
    report: DiagnosticReport, evidence: EvidenceBundle
) -> DiagnosticReport:
    """Attach a deterministic evidence chain and bounded next steps."""

    reasoning = report.derived_findings
    if not reasoning and report.outcome is Outcome.INCONCLUSIVE:
        reasoning = (
            "Validation and completeness checks prevented the rule from reaching a "
            "definitive outcome.",
        )
    explanation = DiagnosticExplanation(
        reasoning=reasoning,
        establishes=_established(report),
        does_not_establish=_does_not_establish(report),
        missing_evidence=_missing_evidence(report),
    )
    return replace(
        report,
        explanation=explanation,
        investigation_guidance=_guidance(report, evidence),
    )
