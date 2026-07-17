"""identity-aiops — governed Keycloak + authentik identity operations for AI agents.

Standalone and self-contained: the governance harness (audit, token budget,
undo-token recording, graduated risk tiers, output sanitize) is
bundled under ``identity_aiops.governance`` — this package has no external
skill-family dependency. Preview: not yet full-coverage.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("identity-aiops")
except PackageNotFoundError:  # running from an uninstalled source tree
    __version__ = "0.0.0+unknown"
