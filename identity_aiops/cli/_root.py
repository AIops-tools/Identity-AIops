"""Top-level Typer app: assembles sub-apps and top-level commands."""

from __future__ import annotations

import typer

from identity_aiops.cli._common import cli_errors
from identity_aiops.cli.clients import clients_app
from identity_aiops.cli.doctor import doctor_cmd
from identity_aiops.cli.events import events_cmd
from identity_aiops.cli.init import init_cmd
from identity_aiops.cli.overview import overview_cmd
from identity_aiops.cli.secret import secret_app
from identity_aiops.cli.undo import undo_app
from identity_aiops.cli.users import users_app

app = typer.Typer(
    name="identity-aiops",
    help="Governed AI-ops for Keycloak + authentik: users, sessions, auth "
    "events, OAuth clients, MFA coverage, and governed identity writes "
    "(disable/enable, session revoke, reset, redirect URIs, secret rotation).",
    no_args_is_help=True,
)

app.add_typer(users_app, name="users")
app.add_typer(clients_app, name="clients")
app.add_typer(secret_app, name="secret")
app.add_typer(undo_app, name="undo")
app.command("init")(init_cmd)
app.command("overview")(overview_cmd)
app.command("events")(events_cmd)
app.command("doctor")(doctor_cmd)


@app.command("mcp")
@cli_errors
def mcp_cmd() -> None:
    """Start the MCP server (stdio transport).

    Single-command entry point for MCP clients (does not go through uvx/PyPI
    resolution at launch):
        identity-aiops mcp
    """
    import sys

    if sys.version_info < (3, 11):
        typer.echo(
            f"ERROR: identity-aiops requires Python >= 3.11 "
            f"(got {sys.version_info.major}.{sys.version_info.minor}).\n"
            f"Fix: uv python install 3.12 && "
            f"uv tool install --python 3.12 --force identity-aiops",
            err=True,
        )
        raise typer.Exit(2)

    from mcp_server.server import main as _mcp_main

    _mcp_main()


if __name__ == "__main__":
    app()
