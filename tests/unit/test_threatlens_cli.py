from __future__ import annotations

import json

from click.testing import CliRunner

from threatlens.cli.main import app


runner = CliRunner()


def test_triage_incident_command_outputs_report() -> None:
    result = runner.invoke(app, ["triage-incident", "INC-1001"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["report_type"] == "incident_triage"
    assert payload["target"] == "INC-1001"


def test_resolve_entity_command_outputs_report() -> None:
    result = runner.invoke(app, ["resolve-entity", "user@contoso.com"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["report_type"] == "entity_resolution"
    assert payload["metadata"]["type"] == "identity"


def test_investigate_resource_command_outputs_findings() -> None:
    resource_id = "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm01"
    result = runner.invoke(app, ["investigate-resource", resource_id])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["report_type"] == "resource_investigation"
    assert len(payload["findings"]) >= 1
