"""Environment and connectivity diagnostics for Identity AIops."""

from __future__ import annotations

from rich.console import Console

from identity_aiops.config import CONFIG_FILE, ENV_FILE, load_config
from identity_aiops.secretstore import SECRETS_FILE, check_permissions, has_store

_console = Console()


def run_doctor(skip_auth: bool = False) -> int:
    """Check config, secrets, and (optionally) connectivity + auth.

    The connectivity probe exercises the full auth path per platform (Keycloak:
    client-credentials token acquisition; authentik: bearer token) followed by
    a cheap realm probe — the user count. Returns a process exit code:
    0 healthy, 1 problems found. Connectivity failures are reported as status,
    never raised as tracebacks (a doctor must survive the thing it diagnoses
    being unhealthy).
    """
    problems = 0

    if not CONFIG_FILE.exists():
        _console.print(f"[red]✗ Config file missing: {CONFIG_FILE}[/]")
        _console.print("[yellow]  Run 'identity-aiops init' to set up your first target.[/]")
        return 1
    _console.print(f"[green]✓ Config file present: {CONFIG_FILE}[/]")

    try:
        config = load_config()
    except Exception as exc:  # noqa: BLE001 — report, do not crash
        _console.print(f"[red]✗ Config load failed: {exc}[/]")
        return 1

    if not config.targets:
        _console.print("[red]✗ No targets configured[/]")
        return 1
    _console.print(f"[green]✓ {len(config.targets)} target(s) configured[/]")

    if has_store():
        _console.print(f"[green]✓ Encrypted secret store present: {SECRETS_FILE}[/]")
        perm_warning = check_permissions()
        if perm_warning:
            _console.print(f"[yellow]! {perm_warning}[/]")
    elif ENV_FILE.exists():
        _console.print(
            f"[yellow]! Using legacy plaintext .env ({ENV_FILE}). Migrate with "
            f"'identity-aiops secret migrate'.[/]"
        )
    else:
        _console.print(
            "[yellow]! No secret store yet. Run 'identity-aiops init' to set up "
            "credentials (stored encrypted).[/]"
        )
        problems += 1

    for target in config.targets:
        try:
            _ = target.secret
            _console.print(
                f"[green]✓ Secret present for '{target.name}' ({target.platform})[/]"
            )
        except OSError as exc:
            _console.print(f"[red]✗ {exc}[/]")
            problems += 1

    if skip_auth:
        _console.print("[dim]Skipping connectivity check (--skip-auth).[/]")
        return 1 if problems else 0

    from identity_aiops.connection import ConnectionManager
    from identity_aiops.ops import users as user_ops

    mgr = ConnectionManager(config)
    for target in config.targets:
        try:
            conn = mgr.connect(target.name)
            # Full auth path + a cheap realm probe: the user count.
            out = user_ops.user_count(conn)
            if "error" in out:
                raise ConnectionError(out["error"])
            _console.print(
                f"[green]✓ Connected to '{target.name}' ({target.platform} "
                f"{target.base_url}, realm '{target.realm}') — auth OK, "
                f"user-count probe OK ({out['count']} users)[/]"
            )
        except Exception as exc:  # noqa: BLE001 — connectivity is a status, not a crash
            _console.print(f"[red]✗ Connect to '{target.name}' failed: {exc}[/]")
            problems += 1

    return 1 if problems else 0
