"""Refuse operations that destroy their own reversibility.

Found live against authentik: disabling the account whose token the tool holds
succeeded, and the undo (enable_user) then failed 403 — the tool had revoked its
own credential mid-flight and could not roll back. A governed, reversible tool
must not offer an action that removes the ability to reverse it.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from identity_aiops.ops.writes import SelfLockout, disable_user


def _conn(self_id, *, platform="authentik"):
    c = MagicMock(name="conn")
    c.self_user_id.return_value = self_id
    c.get.return_value = {"pk": "other", "is_active": True, "enabled": True}
    return c


@pytest.mark.unit
def test_disabling_own_account_is_refused():
    with pytest.raises(SelfLockout, match="account this tool authenticates as"):
        disable_user(_conn("3"), "3")


@pytest.mark.unit
def test_the_refusal_says_why_and_what_to_do_instead():
    with pytest.raises(SelfLockout) as ei:
        disable_user(_conn("3"), "3")
    msg = str(ei.value)
    assert "403" in msg, "must name the concrete failure the operator would hit"
    assert "different administrative credential" in msg, "must offer a way forward"


@pytest.mark.unit
def test_other_accounts_are_not_blocked():
    """The guard must be exact — over-blocking would break normal containment."""
    conn = _conn("3")
    disable_user(conn, "4")  # must not raise
    conn.self_user_id.assert_called()


@pytest.mark.unit
def test_unknown_identity_does_not_block():
    """If self-identity can't be determined, proceed — unknown is not 'it is me'."""
    disable_user(_conn(None), "4")  # must not raise


@pytest.mark.unit
def test_id_comparison_is_type_insensitive():
    """authentik pks are ints in some payloads, strings in others."""
    with pytest.raises(SelfLockout):
        disable_user(_conn(3), "3")
