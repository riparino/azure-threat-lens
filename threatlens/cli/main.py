from __future__ import annotations

import typer

from threatlens.cli.commands import (
    investigate_identity,
    investigate_resource,
    resolve_entity,
    triage_incident,
)

app = typer.Typer(help="Azure Threat Lens investigation CLI")


@app.command("triage-incident")
def triage_incident_cmd(incident_id: str) -> None:
    triage_incident(incident_id)


@app.command("resolve-entity")
def resolve_entity_cmd(entity: str) -> None:
    resolve_entity(entity)


@app.command("investigate-identity")
def investigate_identity_cmd(identity: str) -> None:
    investigate_identity(identity)


@app.command("investigate-resource")
def investigate_resource_cmd(resource_id: str) -> None:
    investigate_resource(resource_id)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
