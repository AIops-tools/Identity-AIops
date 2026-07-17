"""Tests for ``run_doctor`` — environment and connectivity diagnostics.

Everything is redirected to a tmp dir (config, secret store) and the
connection layer is faked at the ``ConnectionManager`` boundary, so no test
ever touches a real Keycloak/authentik instance or ``~/.identity-aiops``.
"""

from __future__ import annotations

import pytest
import yaml
from rich.console import Console

import identity_aiops.config as config_mod
import identity_aiops.connection as connection_mod
import identity_aiops.doctor as doctor_mod
import identity_aiops.secretstore as ss
from identity_aiops.doctor import run_doctor
from identity_aiops.platform import get_platform

MASTER_PW = "test-master-pw"


@pytest.fixture
def doctor_home(tmp_path, monkeypatch):
    """Isolate config + secret store paths under tmp_path."""
    config_file = tmp_path / "config.yaml"
    env_file = tmp_path / ".env"
    secrets_file = tmp_path / "secrets.enc"
    monkeypatch.setenv("IDENTITY_AIOPS_HOME", str(tmp_path))
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "ENV_FILE", env_file)
    monkeypatch.setattr(doctor_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(doctor_mod, "ENV_FILE", env_file)
    monkeypatch.setattr(doctor_mod, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", env_file)
    monkeypatch.setattr(ss, "_cached", None)
    # Wide console so long messages don't wrap mid-assertion.
    monkeypatch.setattr(doctor_mod, "_console", Console(width=500))
    monkeypatch.delenv("IDENTITY_SSO1_SECRET", raising=False)
    return tmp_path


def _write_config(tmp_path, targets: list[dict]) -> None:
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"targets": targets}), "utf-8")


def _seed_secret(monkeypatch, name: str = "sso1", value: str = "client-secret-1") -> None:
    monkeypatch.setenv("IDENTITY_AIOPS_MASTER_PASSWORD", MASTER_PW)
    ss.SecretStore.unlock(MASTER_PW).set(name, value)


_TARGET = {
    "name": "sso1",
    "platform": "keycloak",
    "base_url": "https://sso.example.com",
    "realm": "master",
    "username": "agent-client",
}


class _FakeConn:
    """A healthy fake: the user-count probe answers (auth implicitly OK)."""

    def __init__(self, target) -> None:
        self.target = target
        self.platform = get_platform(target.platform)

    def path(self, resource, **fmt):
        return self.platform.path(resource, realm=self.target.realm, **fmt)

    def get(self, path, **_kw):
        assert path == self.path("user_count")
        return 17


class _HealthyManager:
    """Stands in for ConnectionManager: every connect() succeeds."""

    def __init__(self, config) -> None:
        self._config = config

    def connect(self, name):
        return _FakeConn(self._config.get_target(name))


class _UnreachableManager:
    """Stands in for ConnectionManager: token acquisition fails."""

    def __init__(self, config) -> None:
        self._config = config

    def connect(self, name):
        raise ConnectionError(
            "Token request failed (401) on Keycloak admin REST API "
            "/realms/master/protocol/openid-connect/token"
        )


@pytest.mark.unit
def test_doctor_missing_config_fails_with_init_hint(doctor_home, capsys):
    assert run_doctor() == 1
    out = capsys.readouterr().out
    assert "Config file missing" in out
    assert "identity-aiops init" in out


@pytest.mark.unit
def test_doctor_config_load_failure_reported_not_raised(doctor_home, capsys):
    (doctor_home / "config.yaml").write_text("targets: [unclosed", "utf-8")
    assert run_doctor() == 1
    assert "Config load failed" in capsys.readouterr().out


@pytest.mark.unit
def test_doctor_no_targets_configured(doctor_home, capsys):
    _write_config(doctor_home, [])
    assert run_doctor() == 1
    assert "No targets configured" in capsys.readouterr().out


@pytest.mark.unit
def test_doctor_all_healthy_exit_zero(doctor_home, monkeypatch, capsys):
    _write_config(doctor_home, [_TARGET])
    _seed_secret(monkeypatch)
    monkeypatch.setattr(connection_mod, "ConnectionManager", _HealthyManager)
    assert run_doctor() == 0
    out = capsys.readouterr().out
    assert "Config file present" in out
    assert "1 target(s) configured" in out
    assert "Encrypted secret store present" in out
    assert "Secret present for 'sso1' (keycloak)" in out
    assert "Connected to 'sso1'" in out
    assert "auth OK" in out
    assert "user-count probe OK (17 users)" in out


@pytest.mark.unit
def test_doctor_skip_auth_skips_connectivity(doctor_home, monkeypatch, capsys):
    _write_config(doctor_home, [_TARGET])
    _seed_secret(monkeypatch)

    def _boom(config):  # doctor must not even construct a manager
        raise AssertionError("ConnectionManager should not be used with --skip-auth")

    monkeypatch.setattr(connection_mod, "ConnectionManager", _boom)
    assert run_doctor(skip_auth=True) == 0
    out = capsys.readouterr().out
    assert "Skipping connectivity check" in out
    assert "Connected" not in out


@pytest.mark.unit
def test_doctor_token_failure_exit_one(doctor_home, monkeypatch, capsys):
    _write_config(doctor_home, [_TARGET])
    _seed_secret(monkeypatch)
    monkeypatch.setattr(connection_mod, "ConnectionManager", _UnreachableManager)
    assert run_doctor() == 1
    out = capsys.readouterr().out
    assert "Connect to 'sso1' failed" in out
    assert "Token request failed" in out


@pytest.mark.unit
def test_doctor_probe_error_dict_counts_as_problem(doctor_home, monkeypatch, capsys):
    """A reachable IdP whose probe returns {'error': ...} is still unhealthy."""
    _write_config(doctor_home, [_TARGET])
    _seed_secret(monkeypatch)

    class _BrokenProbeConn(_FakeConn):
        def get(self, path, **_kw):
            raise TimeoutError("read timeout after 30s")

    class _Mgr(_HealthyManager):
        def connect(self, name):
            return _BrokenProbeConn(self._config.get_target(name))

    monkeypatch.setattr(connection_mod, "ConnectionManager", _Mgr)
    assert run_doctor() == 1
    assert "failed" in capsys.readouterr().out


@pytest.mark.unit
def test_doctor_no_secret_store_and_no_secret(doctor_home, capsys):
    _write_config(doctor_home, [_TARGET])
    assert run_doctor(skip_auth=True) == 1
    out = capsys.readouterr().out
    assert "No secret store yet" in out
    assert "No secret for target 'sso1'" in out


@pytest.mark.unit
def test_doctor_legacy_env_file_warns_migrate(doctor_home, monkeypatch, capsys):
    _write_config(doctor_home, [_TARGET])
    (doctor_home / ".env").write_text("IDENTITY_SSO1_SECRET=legacy\n", "utf-8")
    monkeypatch.setenv("IDENTITY_SSO1_SECRET", "legacy")
    assert run_doctor(skip_auth=True) == 0
    out = capsys.readouterr().out
    assert "legacy plaintext .env" in out
    assert "secret migrate" in out


@pytest.mark.unit
def test_doctor_warns_on_loose_secret_permissions(doctor_home, monkeypatch, capsys):
    _write_config(doctor_home, [_TARGET])
    _seed_secret(monkeypatch)
    (doctor_home / "secrets.enc").chmod(0o644)
    assert run_doctor(skip_auth=True) == 0
    assert "should be 600" in capsys.readouterr().out


@pytest.mark.unit
def test_cli_doctor_command_exits_with_doctor_code(doctor_home, monkeypatch):
    from typer.testing import CliRunner

    from identity_aiops.cli import app

    _write_config(doctor_home, [_TARGET])
    _seed_secret(monkeypatch)
    result = CliRunner().invoke(app, ["doctor", "--skip-auth"])
    assert result.exit_code == 0
    assert "Skipping connectivity check" in result.output
