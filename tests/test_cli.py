from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from kubetrace.cli import main

FIXTURES = Path(__file__).parents[1] / "fixtures"


def load_fixture(filename: str = "service-no-ready-endpoints.json") -> dict[str, Any]:
    return json.loads((FIXTURES / filename).read_text(encoding="utf-8"))


def write_fixture(tmp_path: Path, evidence: dict[str, Any]) -> Path:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("filename", "outcome"),
    [
        ("service-no-ready-endpoints.json", "finding"),
        ("service-with-ready-endpoint.json", "no_finding"),
    ],
)
def test_cli_checked_in_fixture_outcomes(filename: str, outcome: str, capsys) -> None:
    exit_status = main([str(FIXTURES / filename)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_status == 0
    assert payload["schemaVersion"] == "kubetrace.report/v1"
    assert payload["outcome"] == outcome
    assert "SERVICE_NO_READY_ENDPOINTS" in captured.err


def test_cli_inconclusive_exit_status(tmp_path: Path, capsys) -> None:
    evidence = load_fixture()
    evidence["collection"]["status"] = "incomplete"

    exit_status = main([str(write_fixture(tmp_path, evidence))])

    assert exit_status == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "inconclusive"


def test_cli_not_applicable_exit_status(tmp_path: Path, capsys) -> None:
    evidence = load_fixture()
    evidence["service"]["spec"] = {
        "type": "ExternalName",
        "externalName": "example.invalid",
    }

    exit_status = main([str(write_fixture(tmp_path, evidence))])

    assert exit_status == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "not_applicable"


def test_cli_malformed_json_has_error_shape_and_nonzero_status(
    tmp_path: Path, capsys
) -> None:
    fixture = tmp_path / "malformed.json"
    fixture.write_text("{not-json", encoding="utf-8")

    exit_status = main([str(fixture)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_status == 2
    assert payload["outcome"] == "validation_error"
    assert payload["service"] is None
    assert payload["errors"]
    assert payload["observedEvidence"] == []
    assert "VALIDATION_ERROR" in captured.err


def test_cli_structurally_invalid_input_is_nonzero(tmp_path: Path, capsys) -> None:
    fixture = write_fixture(tmp_path, {})

    exit_status = main([str(fixture)])

    captured = capsys.readouterr()
    assert exit_status == 2
    assert json.loads(captured.out)["outcome"] == "validation_error"


def test_cli_missing_path_is_nonzero_and_terminal_safe(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.json"

    exit_status = main([str(missing)])

    captured = capsys.readouterr()
    assert exit_status == 2
    assert json.loads(captured.out)["outcome"] == "validation_error"
    assert "cannot read fixture" in captured.err


def test_cli_output_is_deterministic(tmp_path: Path, capsys) -> None:
    evidence = load_fixture()
    reordered = deepcopy(evidence)
    reordered["endpointSliceList"]["items"].reverse()
    fixture = write_fixture(tmp_path, reordered)

    assert main([str(fixture)]) == 0
    first = capsys.readouterr()
    assert main([str(fixture)]) == 0
    second = capsys.readouterr()

    assert first.out == second.out
    assert first.err == second.err
