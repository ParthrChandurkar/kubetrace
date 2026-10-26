"""Deterministic JSON and terminal rendering."""

from __future__ import annotations

import json
from typing import Any

from kubetrace.models import REPORT_SCHEMA_VERSION, RULE_ID, DiagnosticReport, Outcome


def report_payload(report: DiagnosticReport) -> dict[str, Any]:
    """Convert a diagnostic report to its versioned public representation."""

    explanation = report.explanation
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "ruleId": report.rule_id,
        "outcome": report.outcome.value,
        "summary": report.summary,
        "target": {
            "namespace": report.target.namespace,
            "serviceName": report.target.service_name,
        },
        "service": (
            {
                "namespace": report.service.namespace,
                "name": report.service.name,
                "uid": report.service.uid,
            }
            if report.service is not None
            else None
        ),
        "collectionIssues": [
            {
                "operation": issue.operation,
                "code": issue.code,
                "message": issue.message,
                "status": issue.status,
            }
            for issue in report.collection_issues
        ],
        "observedEvidence": [
            {
                "statement": item.statement,
                "source": item.source,
                "sourceCollectedAt": item.source_collected_at,
                "collectedAt": item.collected_at,
                "resource": item.resource,
                "transformations": list(item.transformations),
            }
            for item in report.observed_evidence
        ],
        "derivedFindings": list(report.derived_findings),
        "possibleCauses": list(report.possible_causes),
        "confirmedCauses": list(report.confirmed_causes),
        "limitations": list(report.limitations),
        "explanation": (
            {
                "supportingEvidence": [
                    {
                        "source": item.source,
                        "sourceCollectedAt": item.source_collected_at,
                        "resource": item.resource,
                        "statement": item.statement,
                    }
                    for item in report.observed_evidence
                ],
                "reasoning": list(explanation.reasoning),
                "establishes": list(explanation.establishes),
                "doesNotEstablish": list(explanation.does_not_establish),
                "missingEvidence": list(explanation.missing_evidence),
            }
            if explanation is not None
            else None
        ),
        "investigationGuidance": list(report.investigation_guidance),
        "errors": [],
    }


def validation_error_payload(errors: tuple[str, ...]) -> dict[str, Any]:
    """Build the stable CLI payload used for invalid fixture evidence."""

    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "ruleId": RULE_ID,
        "outcome": Outcome.VALIDATION_ERROR.value,
        "summary": "Evidence is invalid.",
        "target": None,
        "service": None,
        "collectionIssues": [],
        "errors": list(errors),
        "observedEvidence": [],
        "derivedFindings": [],
        "possibleCauses": [],
        "confirmedCauses": [],
        "limitations": [],
        "explanation": {
            "supportingEvidence": [],
            "reasoning": [],
            "establishes": [],
            "doesNotEstablish": [
                "Invalid input cannot support a diagnostic conclusion."
            ],
            "missingEvidence": [
                "Valid evidence is required before diagnostic rules can run."
            ],
        },
        "investigationGuidance": [
            "Correct the reported validation errors and rerun the investigation."
        ],
    }


def to_json(payload: dict[str, Any]) -> str:
    """Serialize report data deterministically."""

    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
