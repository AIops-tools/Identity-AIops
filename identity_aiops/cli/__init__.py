"""CLI package for identity-aiops.

Re-exports ``app`` so the pyproject entry point
``identity-aiops = "identity_aiops.cli:app"`` works unchanged.
"""

from identity_aiops.cli._root import app

__all__ = ["app"]
