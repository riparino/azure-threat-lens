from __future__ import annotations

import click

from threatlens.cli import commands


@click.group(help="Azure Threat Lens security investigation CLI")
def app() -> None:
    pass


@app.command("triage-incident")
@click.argument("incident_id")
def triage_incident(incident_id: str) -> None:
    click.echo(commands.triage_incident(incident_id))


@app.command("resolve-entity")
@click.argument("entity")
def resolve_entity(entity: str) -> None:
    click.echo(commands.resolve_entity(entity))


@app.command("investigate-identity")
@click.argument("identity")
def investigate_identity(identity: str) -> None:
    click.echo(commands.investigate_identity(identity))


@app.command("investigate-resource")
@click.argument("resource_id")
def investigate_resource(resource_id: str) -> None:
    click.echo(commands.investigate_resource(resource_id))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
