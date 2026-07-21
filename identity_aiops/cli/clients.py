"""``identity-aiops clients`` — list / inspect OAuth clients and governed writes.

Read commands print normalized JSON; write commands preview with ``--dry-run``
and, once double-confirmed, delegate real execution to the governed MCP twins
so every CLI write lands in the audit log with undo where applicable.
"""

from __future__ import annotations

import json
from typing import Annotated

import typer

from identity_aiops.cli._common import (
    DryRunOption,
    TargetOption,
    cli_errors,
    console,
    double_confirm,
    dry_run_preview,
    get_connection,
    print_result,
)

clients_app = typer.Typer(
    name="clients",
    help="OAuth/OIDC clients: list, detail, and governed writes "
    "(redirect-URI update, secret rotation).",
    no_args_is_help=True,
)


@clients_app.command("list")
@cli_errors
def clients_list(
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max clients")] = 200,
    target: TargetOption = None,
) -> None:
    """List OAuth/OIDC clients in the realm."""
    from identity_aiops.ops import clients as ops

    conn, _ = get_connection(target)
    print_result(ops.list_clients(conn, limit))


@clients_app.command("show")
@cli_errors
def clients_show(
    client_id: Annotated[str, typer.Argument(help="Client internal id (from 'clients list')")],
    target: TargetOption = None,
) -> None:
    """Show one client's normalized detail."""
    from identity_aiops.ops import clients as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.client_detail(conn, client_id)))


@clients_app.command("set-redirect-uris")
@cli_errors
def clients_set_redirect_uris(
    client_id: Annotated[str, typer.Argument(help="Client internal id")],
    uris: Annotated[
        list[str], typer.Option("--uri", "-u", help="Redirect URI (repeat; FULL new list)")
    ],
    target: TargetOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Replace a client's redirect-URI list (high risk)."""
    from mcp_server.tools import writes as gov

    if dry_run:
        dry_run_preview(
            gov.update_client_redirect_uris(client_id=client_id, redirect_uris=list(uris),
                                            dry_run=True, target=target),
            operation="update_client_redirect_uris",
            api_call="replace redirect URIs",
            parameters={"client_id": client_id, "redirect_uris": uris})
        return
    double_confirm("replace redirect URIs on client", client_id)
    console.print_json(json.dumps(
        gov.update_client_redirect_uris(client_id=client_id, redirect_uris=list(uris),
                                        target=target)
    ))


@clients_app.command("rotate-secret")
@cli_errors
def clients_rotate_secret(
    client_id: Annotated[str, typer.Argument(help="Client internal id")],
    target: TargetOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Rotate a client's secret (irreversible, high risk)."""
    from mcp_server.tools import writes as gov

    if dry_run:
        # Through the governed call: rotate_client_secret is self-lockout guarded,
        # so a preview must report a refusal rather than a green banner.
        dry_run_preview(
            gov.rotate_client_secret(client_id=client_id, dry_run=True, target=target),
            operation="rotate_client_secret", api_call="rotate client secret",
            parameters={"client_id": client_id})
        return
    double_confirm("rotate the secret of client", client_id)
    console.print_json(json.dumps(gov.rotate_client_secret(client_id=client_id, target=target)))
