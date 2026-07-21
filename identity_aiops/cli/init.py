"""``identity-aiops init`` — a friendly, interactive onboarding wizard.

Walks a new user through connecting their first identity-provider target:
collects the non-secret connection details into ``config.yaml`` and the API
secret into the *encrypted* store (never plaintext on disk). Designed to be
run on a terminal; everything it needs is prompted with sensible defaults.
"""

from __future__ import annotations

import getpass

import typer
import yaml

from identity_aiops.cli._common import cli_errors, console
from identity_aiops.config import CONFIG_DIR, CONFIG_FILE, DEFAULT_REALM
from identity_aiops.platform import AUTHENTIK, KEYCLOAK


def _load_existing_targets() -> list[dict]:
    if not CONFIG_FILE.exists():
        return []
    raw = yaml.safe_load(CONFIG_FILE.read_text("utf-8")) or {}
    return list(raw.get("targets", []))


def _write_targets(targets: list[dict]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass
    CONFIG_FILE.write_text(yaml.safe_dump({"targets": targets}, sort_keys=False), "utf-8")


@cli_errors
def init_cmd() -> None:
    """Interactively set up your first identity-provider connection."""
    from identity_aiops.secretstore import SecretStore, resolve_master_password

    console.print("[bold cyan]Identity AIops — setup wizard[/]")
    console.print(
        "This collects Keycloak or authentik connection details (saved to "
        "config.yaml) and your API secret (saved [bold]encrypted[/] to "
        "secrets.enc).\n"
    )

    console.print("[bold]Step 1 — master password[/]")
    console.print(
        "[dim]Encrypts secrets.enc. You'll set it via the "
        "IDENTITY_AIOPS_MASTER_PASSWORD env var for non-interactive/MCP use.[/]"
    )
    password = resolve_master_password(confirm_if_new=True)
    store = SecretStore.unlock(password)

    targets = _load_existing_targets()
    existing_names = {t.get("name") for t in targets}

    while True:
        console.print("\n[bold]Step 2 — add a target[/]")
        name = typer.prompt("Target name (e.g. sso1)").strip()
        if name in existing_names:
            if not typer.confirm(f"'{name}' already exists — overwrite?", default=False):
                continue
            targets = [t for t in targets if t.get("name") != name]

        platform = typer.prompt(
            f"Platform ({KEYCLOAK} / {AUTHENTIK})", default=KEYCLOAK
        ).strip().lower()
        if platform not in (KEYCLOAK, AUTHENTIK):
            console.print("[red]Platform must be 'keycloak' or 'authentik'.[/]")
            continue

        base_url = typer.prompt(
            "Base URL (e.g. https://sso.example.com)"
        ).strip().rstrip("/")
        console.print("[dim]Lab/self-signed setups can answer No here.[/]")
        verify_ssl = typer.confirm(
            "Verify TLS certificate? (No for self-signed lab certs)", default=True
        )

        realm = DEFAULT_REALM
        username = ""
        if platform == KEYCLOAK:
            realm = typer.prompt("Realm", default=DEFAULT_REALM).strip()
            username = typer.prompt(
                "Client ID (confidential client with service-account admin roles)"
            ).strip()
            prompt = "Client secret"
        else:
            prompt = "authentik API token"
        secret = getpass.getpass(f"{prompt} for '{name}' (hidden): ")
        store = store.set(name, secret)

        entry = {
            "name": name,
            "platform": platform,
            "base_url": base_url,
            "realm": realm,
            "username": username,
            "verify_ssl": verify_ssl,
        }
        targets.append(entry)
        existing_names.add(name)
        _write_targets(targets)
        console.print(f"[green]✓ Saved target '{name}' ({platform}, secret encrypted).[/]")

        if not typer.confirm("\nAdd another target?", default=False):
            break

    console.print(f"\n[green]✓ Setup complete.[/] Config: {CONFIG_FILE}")
    console.print(
        "[dim]Tip: export IDENTITY_AIOPS_MASTER_PASSWORD=... in your shell profile "
        "so the MCP server and CLI can unlock secrets non-interactively.[/]"
    )
    if typer.confirm("Run a connectivity check now (identity-aiops doctor)?", default=True):
        from identity_aiops.doctor import run_doctor

        raise typer.Exit(run_doctor())
