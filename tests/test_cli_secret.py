"""``identity-aiops secret`` command coverage — set / list / rm / migrate /
rotate-password over a throwaway encrypted store. The master password comes
from the env var (non-interactive), and no secret value is ever printed.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

import identity_aiops.cli.secret as secret_cli
import identity_aiops.secretstore as ss

runner = CliRunner()
MASTER = "unit-master-pw"


@pytest.fixture
def store_home(tmp_path, monkeypatch):
    secrets_file = tmp_path / "secrets.enc"
    env_file = tmp_path / ".env"
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", env_file)
    monkeypatch.setattr(ss, "_cached", None)
    # secret_cli imported SECRETS_FILE by name — keep it in sync for the echo.
    monkeypatch.setattr(secret_cli, "SECRETS_FILE", secrets_file)
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, MASTER)
    return tmp_path


@pytest.mark.unit
def test_secret_set_list_rm_roundtrip(store_home):
    from identity_aiops.cli import app

    r = runner.invoke(app, ["secret", "set", "sso1", "--value", "s3cr3t-value"])
    assert r.exit_code == 0, r.output
    assert "s3cr3t-value" not in r.output  # value never echoed

    r = runner.invoke(app, ["secret", "list"])
    assert r.exit_code == 0 and "sso1" in r.output

    # value stays encrypted on disk
    assert b"s3cr3t-value" not in (store_home / "secrets.enc").read_bytes()

    r = runner.invoke(app, ["secret", "rm", "sso1"])
    assert r.exit_code == 0
    r = runner.invoke(app, ["secret", "list"])
    assert "No secrets stored" in r.output


@pytest.mark.unit
def test_secret_set_prompts_when_value_omitted(store_home, monkeypatch):
    from identity_aiops.cli import app

    monkeypatch.setattr(secret_cli.getpass, "getpass", lambda prompt="": "prompted-key")
    r = runner.invoke(app, ["secret", "set", "sso2"])
    assert r.exit_code == 0, r.output
    assert ss.get_secret("sso2") == "prompted-key"


@pytest.mark.unit
def test_secret_migrate_imports_legacy_env(store_home):
    from identity_aiops.cli import app

    (store_home / ".env").write_text("IDENTITY_SSO3_SECRET=legacy-tok\n")
    r = runner.invoke(app, ["secret", "migrate"])
    assert r.exit_code == 0, r.output
    assert "sso3" in r.output
    assert ss.get_secret("sso3") == "legacy-tok"

    # nothing left to migrate on a second run
    r = runner.invoke(app, ["secret", "migrate"])
    assert "Nothing to migrate" in r.output


@pytest.mark.unit
def test_secret_rotate_password_reencrypts(store_home, monkeypatch):
    from identity_aiops.cli import app

    ss.SecretStore.unlock(MASTER).set("sso4", "keep-me")

    # unlock uses env password; then two matching new-password prompts.
    monkeypatch.setattr(secret_cli.getpass, "getpass",
                        lambda prompt="": "new-master-pw")
    r = runner.invoke(app, ["secret", "rotate-password"])
    assert r.exit_code == 0, r.output
    assert ss.SecretStore.unlock("new-master-pw").get("sso4") == "keep-me"


@pytest.mark.unit
def test_secret_rotate_password_mismatch_aborts(store_home, monkeypatch):
    from identity_aiops.cli import app

    ss.SecretStore.unlock(MASTER).set("sso5", "x")
    answers = iter(["new-pw-1", "different-pw"])
    monkeypatch.setattr(secret_cli.getpass, "getpass",
                        lambda prompt="": next(answers))
    r = runner.invoke(app, ["secret", "rotate-password"])
    assert r.exit_code == 1
    assert "did not match" in r.output
