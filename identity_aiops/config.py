"""Configuration management for Identity AIops.

Loads identity-provider connection targets from a YAML config file. Each target
names its ``platform`` — ``keycloak`` (admin REST API) or ``authentik`` (API
v3) — so one config can span a mixed estate. See
:mod:`identity_aiops.platform` for how the platform name selects the API shape
(auth flow + resource paths).

A target carries its ``base_url`` (e.g. ``https://sso.example.com``) and, for
Keycloak, the ``realm`` the admin API calls are scoped to (default
``master``) plus the ``client_id`` used for the client-credentials grant
(stored in ``username``). TLS verification defaults to ON.

The secret is NEVER stored in the config file or in plaintext on disk: it lives
in the encrypted store ``~/.identity-aiops/secrets.enc`` (see
:mod:`identity_aiops.secretstore`). For Keycloak the secret is the confidential
client's **client secret**; for authentik it is the **API token**. A legacy env
var (``IDENTITY_<TARGET>_SECRET``) is honoured as a fallback.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from identity_aiops.governance.paths import ops_home
from identity_aiops.platform import KEYCLOAK, PLATFORMS, get_platform
from identity_aiops.secretstore import SecretStoreError, get_secret, has_store

if TYPE_CHECKING:
    from identity_aiops.platform import Platform

CONFIG_DIR = ops_home()
CONFIG_FILE = CONFIG_DIR / "config.yaml"
ENV_FILE = CONFIG_DIR / ".env"

SECRET_ENV_PREFIX = "IDENTITY_"  # nosec B105 — env-var name, not a secret
SECRET_ENV_SUFFIX = "_SECRET"  # nosec B105 — env-var name, not a secret

DEFAULT_REALM = "master"

_log = logging.getLogger("identity-aiops.config")


def _secret_env_key(name: str) -> str:
    """Legacy per-target secret env var name, e.g. IDENTITY_SSO1_SECRET."""
    return f"{SECRET_ENV_PREFIX}{name.upper().replace('-', '_')}{SECRET_ENV_SUFFIX}"


def _resolve_secret(name: str) -> str:
    """Return a target's secret: encrypted store first, then legacy env var."""
    if has_store():
        try:
            return get_secret(name)
        except SecretStoreError:
            pass  # fall through to legacy env var
    legacy = os.environ.get(_secret_env_key(name))
    if legacy:
        _log.warning(
            "Using plaintext env var %s. Migrate to the encrypted store with "
            "'identity-aiops secret migrate'.",
            _secret_env_key(name),
        )
        return legacy
    raise OSError(
        f"No secret for target '{name}'. Add one with "
        f"'identity-aiops secret set {name}' (stored encrypted), or run "
        f"'identity-aiops init'."
    )


@dataclass(frozen=True)
class TargetConfig:
    """A connection target for one identity provider.

    ``platform`` is ``keycloak`` or ``authentik`` (validated at construction).
    ``username`` holds the Keycloak **client_id** for the client-credentials
    grant (unused for authentik); the secret (Keycloak client secret /
    authentik API token) comes from the encrypted store. ``realm`` scopes every
    Keycloak admin call (authentik has no realms; the field is ignored there).
    """

    name: str
    platform: str = KEYCLOAK
    base_url: str = ""
    realm: str = DEFAULT_REALM
    username: str = ""
    verify_ssl: bool = True

    def __post_init__(self) -> None:
        if self.platform not in PLATFORMS:
            raise ValueError(
                f"Target '{self.name}': platform must be one of {PLATFORMS}, "
                f"got '{self.platform}'."
            )
        if not self.base_url:
            raise ValueError(
                f"Target '{self.name}': base_url is required "
                f"(e.g. https://sso.example.com)."
            )
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))
        if not self.realm:
            object.__setattr__(self, "realm", DEFAULT_REALM)

    @property
    def platform_obj(self) -> Platform:
        return get_platform(self.platform)

    @property
    def secret(self) -> str:
        return _resolve_secret(self.name)


@dataclass(frozen=True)
class AppConfig:
    """Top-level application config."""

    targets: tuple[TargetConfig, ...] = ()

    def get_target(self, name: str) -> TargetConfig:
        for t in self.targets:
            if t.name == name:
                return t
        available = ", ".join(t.name for t in self.targets) or "(none)"
        raise KeyError(f"Target '{name}' not found. Available: {available}")

    @property
    def default_target(self) -> TargetConfig:
        if not self.targets:
            raise ValueError("No targets configured. Check config.yaml")
        return self.targets[0]


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load config from YAML; the secret comes from the encrypted store."""
    path = config_path or CONFIG_FILE
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"Run 'identity-aiops init' to set up a Keycloak or authentik "
            f"target, or create {CONFIG_FILE} with a 'targets' list."
        )

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    targets = tuple(
        TargetConfig(
            name=t["name"],
            platform=t.get("platform", KEYCLOAK),
            base_url=t.get("base_url", ""),
            realm=t.get("realm", DEFAULT_REALM),
            username=t.get("username", ""),
            verify_ssl=t.get("verify_ssl", True),
        )
        for t in raw.get("targets", [])
    )

    return AppConfig(targets=targets)
