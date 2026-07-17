"""Tests for the ``identity-aiops init`` onboarding wizard.

The wizard is driven end-to-end through Typer's CliRunner with every path
(config.yaml, secrets.enc, rules.yaml) isolated under tmp_path. The master
password comes from IDENTITY_AIOPS_MASTER_PASSWORD (the non-interactive path)
and the hidden API-secret prompt is patched at the getpass boundary.
"""

from __future__ import annotations

import getpass as getpass_mod

import pytest
import yaml
from typer.testing import CliRunner

import identity_aiops.cli.init as init_mod
import identity_aiops.config as config_mod
import identity_aiops.doctor as doctor_mod
import identity_aiops.secretstore as ss

MASTER_PW = "init-master-pw"
API_SECRET = "idp-api-secret-0123"

# Wizard answers: name, accept platform default (keycloak), base URL, accept
# TLS-verify default (True), accept realm default (master), client id, no
# second target, decline the trailing doctor run. The API secret itself comes
# via getpass.
WIZARD_INPUT = "sso1\n\nhttps://sso.example.com\n\n\nagent-client\nn\nn\n"


@pytest.fixture
def init_home(tmp_path, monkeypatch):
    """Isolate config + secret store + governance home under tmp_path."""
    config_file = tmp_path / "config.yaml"
    secrets_file = tmp_path / "secrets.enc"
    monkeypatch.setenv("IDENTITY_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv("IDENTITY_AIOPS_MASTER_PASSWORD", MASTER_PW)
    monkeypatch.setattr(init_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(init_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    # The hidden API-secret prompt bypasses CliRunner stdin.
    monkeypatch.setattr(getpass_mod, "getpass", lambda prompt="": API_SECRET)
    return tmp_path


def _run_init(input_text: str = WIZARD_INPUT):
    from identity_aiops.cli import app

    return CliRunner().invoke(app, ["init"], input=input_text)


@pytest.mark.unit
def test_init_writes_config_with_entered_values(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"] == [
        {
            "name": "sso1",
            "platform": "keycloak",
            "base_url": "https://sso.example.com",
            "realm": "master",  # accepted realm default must land
            "username": "agent-client",
            "verify_ssl": True,  # accepted TLS confirm default=True must land
        }
    ]


@pytest.mark.unit
def test_init_tls_confirm_can_be_declined_for_lab_certs(init_home):
    result = _run_init("sso1\n\nhttps://sso.example.com\nn\n\nagent-client\nn\nn\n")
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"][0]["verify_ssl"] is False


@pytest.mark.unit
def test_init_authentik_branch_skips_realm_and_client_id(init_home):
    result = _run_init("ak1\nauthentik\nhttps://auth.example.com\n\nn\nn\n")
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"][0]["platform"] == "authentik"
    assert raw["targets"][0]["username"] == ""  # authentik uses only the API token
    assert ss.SecretStore.unlock(MASTER_PW).get("ak1") == API_SECRET


@pytest.mark.unit
def test_init_rejects_unknown_platform_then_reprompts(init_home):
    result = _run_init(
        "sso1\nokta\nsso1\n\nhttps://sso.example.com\n\n\nagent-client\nn\nn\n"
    )
    assert result.exit_code == 0, result.output
    assert "Platform must be 'keycloak' or 'authentik'." in result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert [t["name"] for t in raw["targets"]] == ["sso1"]


@pytest.mark.unit
def test_init_stores_secret_encrypted_not_in_config(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    # API secret is readable back through the secret store API...
    assert ss.SecretStore.unlock(MASTER_PW).get("sso1") == API_SECRET
    # ...and never lands in plaintext in config.yaml or secrets.enc.
    assert API_SECRET not in (init_home / "config.yaml").read_text("utf-8")
    assert API_SECRET not in (init_home / "secrets.enc").read_text("utf-8")


@pytest.mark.unit
def test_init_seeds_default_rules_with_dual_control_tier(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    rules = yaml.safe_load((init_home / "rules.yaml").read_text("utf-8"))
    tiers = {r["name"]: r for r in rules["risk_tiers"]}
    assert "high-risk-requires-approver" in tiers
    assert tiers["high-risk-requires-approver"]["tier"] == "dual"
    assert tiers["high-risk-requires-approver"]["min_risk_level"] == "high"


@pytest.mark.unit
def test_init_rerun_does_not_clobber_existing_rules(init_home):
    sentinel = "# operator-authored rules — must survive re-init\nrisk_tiers: []\n"
    (init_home / "rules.yaml").write_text(sentinel, "utf-8")
    result = _run_init()
    assert result.exit_code == 0, result.output
    assert (init_home / "rules.yaml").read_text("utf-8") == sentinel


@pytest.mark.unit
def test_init_accepting_doctor_confirm_runs_doctor(init_home, monkeypatch):
    calls: list[bool] = []
    monkeypatch.setattr(doctor_mod, "run_doctor", lambda: calls.append(True) or 0)
    # Empty last answer accepts the confirm's default=True.
    result = _run_init("sso1\n\nhttps://sso.example.com\n\n\nagent-client\nn\n\n")
    assert result.exit_code == 0, result.output
    assert calls == [True]


@pytest.mark.unit
def test_init_overwrite_existing_target(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    # Same name again: confirm overwrite, new base URL, accept defaults.
    result = _run_init(
        "sso1\ny\n\nhttps://sso-new.example.com\n\n\nagent-client\nn\nn\n"
    )
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert [t["base_url"] for t in raw["targets"]] == ["https://sso-new.example.com"]
