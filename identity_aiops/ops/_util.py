"""Shared helpers for the identity ops modules.

Keycloak and authentik return the same identity concepts under different JSON
field names (e.g. a user's active state is Keycloak ``enabled`` vs authentik
``is_active``; timestamps are Keycloak epoch-millis vs authentik ISO-8601).
The ops modules stay platform-neutral by asking the connection for paths
(see :mod:`identity_aiops.platform`) and by reading fields through
:func:`pick` / :func:`user_enabled` / :func:`epoch_seconds`, which reconcile
the conventions. All IdP text reaches the caller only after ``sanitize()``
via ``s``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from identity_aiops.governance import opt_str, sanitize


def as_obj(data: Any) -> dict:
    """Return ``data`` as a dict (empty dict if it isn't one)."""
    return data if isinstance(data, dict) else {}


def s(value: Any, limit: int = 256) -> str:
    """Sanitize an arbitrary value to a bounded, injection-safe string."""
    return sanitize(str(value if value is not None else ""), limit)


def opt_s(value: Any, limit: int = 256) -> str | None:
    """Sanitize an *optional* IdP field, preserving absence as ``None``.

    Companion to :func:`s`, which folds a missing field into ``""``. That
    conflation is invisible to the caller: an empty string reads as "the IdP
    returned this field and it is blank", when the truth may be "Keycloak has
    no such field / authentik never populated it". A consumer — a smaller local
    model especially — cannot recover the difference and tends to invent one.

    Use this for every optional field on a normalized row (a user's email, an
    event's client, a session's last-access time); keep :func:`s` for values
    that are always present, such as a caller-supplied id being echoed back.
    """
    return opt_str(value, limit)


def pick(row: dict, *keys: str, default: Any = None) -> Any:
    """Return the first present, non-None value among ``keys`` (else ``default``)."""
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return default


_TRUE = {"1", "true", "yes", "on", "enabled", "up", "active", "confirmed"}
_FALSE = {"0", "false", "no", "off", "disabled", "down", "", "none"}


def to_bool(value: Any) -> bool:
    """Coerce an IdP truthy/falsy cell (``"1"``, ``true``, ``"yes"``) to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return bool(text)


def user_enabled(row: dict) -> bool:
    """Read a user's effective enabled state across both platforms.

    Keycloak exposes ``enabled`` (boolean); authentik exposes ``is_active``.
    ``enabled`` wins when present, otherwise ``is_active``; absent both, a
    user is assumed enabled (safer for audits: never silently drop rows).
    """
    if "enabled" in row and row["enabled"] is not None:
        return to_bool(row["enabled"])
    if "is_active" in row and row["is_active"] is not None:
        return to_bool(row["is_active"])
    return True


def is_service_account(row: dict) -> bool:
    """Heuristic: is this user row a service account (non-human)?

    Keycloak marks service-account users with ``serviceAccountClientId`` and a
    ``service-account-`` username prefix; authentik carries an explicit
    ``type`` of ``service_account`` / ``internal_service_account``.
    """
    if row.get("serviceAccountClientId"):
        return True
    if "service_account" in str(row.get("type") or "").lower():
        return True
    return str(row.get("username") or "").startswith("service-account-")


def num(value: Any) -> float:
    """Coerce a numeric cell to float; 0.0 when absent/non-numeric."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# Epoch values above this are treated as milliseconds (Keycloak convention).
_EPOCH_MS_CUTOFF = 1e11


def epoch_seconds(value: Any) -> float:
    """Coerce a timestamp to epoch **seconds**; 0.0 when absent/unparseable.

    Accepts Keycloak epoch-millis (``1720000000000``), plain epoch seconds,
    and authentik ISO-8601 strings (``2026-07-01T10:00:00Z``).
    """
    if value is None or value == "":
        return 0.0
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > _EPOCH_MS_CUTOFF else v
    text = str(value).strip()
    try:
        v = float(text)
        return v / 1000.0 if v > _EPOCH_MS_CUTOFF else v
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0
