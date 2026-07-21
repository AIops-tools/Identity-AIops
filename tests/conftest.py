"""Test isolation: redirect the governance harness state at a tmp dir.

Governed-tool calls write an audit row (and, for reversible writes, an undo
token). This autouse fixture points ``IDENTITY_AIOPS_HOME`` at a throwaway
directory and resets the harness singletons so nothing touches the real
``~/.identity-aiops`` during tests.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_harness_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("idp-home")
    monkeypatch.setenv("IDENTITY_AIOPS_HOME", str(home))

    import identity_aiops.governance.audit as audit
    import identity_aiops.governance.undo as undo

    monkeypatch.setattr(audit, "_engine", None, raising=False)
    monkeypatch.setattr(audit, "_DEFAULT_DB", None, raising=False)
    monkeypatch.setattr(undo, "_store", None, raising=False)
    yield


@pytest.fixture(autouse=True)
def _default_approver(monkeypatch):
    """Record a synthetic approver annotation on every test's audit rows.

    IDENTITY_AUDIT_APPROVED_BY is an optional audit annotation now — recorded on
    the row when set, never required and never a gate. Setting it globally keeps
    a stable value in the trail for tests that inspect audit rows; the
    governance-persistence tests clear it to prove a write still runs without
    one."""
    monkeypatch.setenv("IDENTITY_AUDIT_APPROVED_BY", "pytest")
