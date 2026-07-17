---
name: identity-aiops
description: >
  Use this skill whenever the user needs to operate a Keycloak or authentik identity provider — a one-shot overview, realm settings, users with sessions/credentials/groups/lockout status, authentication and admin events, OAuth/OIDC clients, four flagship RCAs (login-failure/lockout-storm, stale access, client misconfiguration, MFA coverage), and governed writes (disable/enable a user, revoke sessions, require a password reset, replace redirect URIs, rotate a client secret).
  Always use this skill for "Keycloak", "authentik", "realm", "SSO users", "login failures", "brute force logins", "locked out users", "stale accounts", "service account misuse", "redirect URI", "PKCE", "implicit flow", "client secret rotation", "MFA coverage", "who has no 2FA" when the context is a Keycloak/authentik IdP.
  Do NOT use when the target is something other than a Keycloak/authentik identity provider (a hypervisor, storage appliance, backup product, container-orchestration cluster, firewall, database, or OT/industrial equipment) — route those to the appropriate other AIops-tools skill. Cloud IdPs (Okta, Entra ID, Auth0) are out of scope.
  Preview — governed identity operations with a built-in governance harness (audit, policy, token budget, undo, risk-tiers). Mock-validated only, not run against a live IdP; both Keycloak and authentik are free/self-hostable, so a self-hosted lab is the easiest live check.
installer:
  kind: uv
  package: identity-aiops
argument-hint: "[a user/client id, a realm, or describe your identity task]"
allowed-tools:
  - Bash
metadata: {"openclaw":{"requires":{"env":["IDENTITY_AIOPS_CONFIG"],"bins":["identity-aiops"],"config":["~/.identity-aiops/config.yaml","~/.identity-aiops/secrets.enc"]},"optional":{"env":["IDENTITY_AIOPS_MASTER_PASSWORD"]},"primaryEnv":"IDENTITY_AIOPS_CONFIG","homepage":"https://github.com/AIops-tools/Identity-AIops","emoji":"🔐","os":["macos","linux"]}}
compatibility: >
  Standalone, self-governed identity-provider operations across Keycloak (admin REST API /admin/realms/{realm}/..., OAuth2 client-credentials grant against the realm token endpoint with automatic refresh-on-401) and authentik (API v3 /api/v3/..., long-lived API token as a Bearer header) — preview. Each target in the config names its own platform, and a name-keyed platform registry selects the API shape, so the same tools work on both and one config can span a mixed estate. The governance harness (audit, policy, token/runaway budget, undo, risk-tiers) is bundled in the package — no external skill-family dependency.
  All write operations are audited to a local SQLite DB under ~/.identity-aiops/ (relocatable via IDENTITY_AIOPS_HOME).
  Credentials: the Keycloak confidential client's client secret or the authentik API token is stored ENCRYPTED in ~/.identity-aiops/secrets.enc (Fernet/AES-128 + scrypt-derived key) — never plaintext on disk. Run 'identity-aiops init' to onboard (it asks for the platform, base URL, and — Keycloak — realm + client_id), or 'identity-aiops secret set <target>' to add one. The store is unlocked by a master password from IDENTITY_AIOPS_MASTER_PASSWORD (non-interactive/MCP/CI) or an interactive prompt (CLI on a TTY). A legacy plaintext env var IDENTITY_<TARGET_NAME_UPPER>_SECRET is still honoured as a fallback with a deprecation warning (migrate with 'identity-aiops secret migrate'). Secrets are held only in memory, never logged or echoed; rotate_client_secret returns and records masked fingerprints only.
  State-changing operations pass through the @governed_tool decorator (pre-check + budget guard + audit + risk-tier gate). enable_user, update_client_redirect_uris, and rotate_client_secret are risk=high with dry_run + an approver gate; revoke_user_sessions and rotate_client_secret are irreversible (priorState only). Reversible writes (disable_user/enable_user, require_password_reset, update_client_redirect_uris) capture the real fetched before-state and record an inverse undo descriptor.
  Webhooks: none — no outbound network calls beyond the configured Keycloak / authentik REST API.
  SSL: verify_ssl defaults to ON; disable only for self-signed lab certs.
  Transitive dependencies: httpx (HTTP client) and the MCP SDK. No post-install scripts or background services.
  PREVIEW: mock-validated only — not run against a live IdP. Both Keycloak and authentik are free/self-hostable, so a self-hosted lab is the easiest live check.
---

# Identity AIops (preview)

> **Disclaimer**: Community-maintained open-source project, **not affiliated with, endorsed by, or sponsored by the Keycloak project, Red Hat, Authentik Security Inc., or the authentik project.** Keycloak and authentik are trademarks of their respective owners. Source at [github.com/AIops-tools/Identity-AIops](https://github.com/AIops-tools/Identity-AIops) under the MIT license.

Governed identity operations — **27 MCP tools** across **Keycloak** (admin REST
`/admin/realms/{realm}/...`) and **authentik** (API v3 `/api/v3/...`), every one
wrapped with the bundled `@governed_tool` harness: a local unified audit log
under `~/.identity-aiops/`, policy engine, token/runaway budget guard,
undo-token recording, and graduated-autonomy risk tiers. A per-target
`platform` field selects the API shape, so the same tools work on both IdPs and
one config can span a mixed estate. The Keycloak client secret / authentik API
token is stored **encrypted** (`~/.identity-aiops/secrets.enc`, Fernet +
scrypt) — never plaintext on disk.

> **Standalone**: the governance harness is bundled in the package
> (`identity_aiops.governance`) — no external skill-family dependency.
> **Preview / mock-only**: not run against a live IdP; both platforms are
> free/self-hostable, so a self-hosted lab is the easiest live check.

## What This Skill Does

| Group | Tools | Count | R/W |
|-------|-------|:-----:|:---:|
| **Realm / system** | identity_overview, realm_info, list_identity_providers | 3 | read |
| **Users / groups** | list_users, user_detail, user_count, user_sessions, user_credentials, list_groups, group_members, user_lockout_status | 8 | read |
| **Events** | login_events, admin_events | 2 | read |
| **Clients** | list_clients, client_detail, client_sessions, client_session_stats | 4 | read |
| **Flagship analyses** | login_failure_rca, stale_access_audit, client_misconfig_audit, mfa_coverage_analysis | 4 | read |
| **Writes** | disable_user, revoke_user_sessions, require_password_reset | 3 | write (med) |
| **Writes** | enable_user, update_client_redirect_uris, rotate_client_secret | 3 | write (**high**) |

The four flagship analyses are transparent heuristics that report their numbers,
never a black-box verdict: `login_failure_rca` windows the failed-auth feed by
user/IP/client and separates password spray, targeted brute-force, a stale
stored credential, a misconfigured client, an expired-credential storm, and a
lockout storm; `stale_access_audit` flags dormant and never-used accounts,
interactive service accounts, and orphaned sessions; `client_misconfig_audit`
ranks clients by OAuth-BCP risk (wildcard/http redirects, secrets in public
clients, implicit flow, missing PKCE, password grant); `mfa_coverage_analysis`
reports second-factor coverage overall and per group.

## Quick Install

```bash
uv tool install identity-aiops
identity-aiops init       # wizard: pick platform (keycloak/authentik) + encrypted secret
identity-aiops doctor
```

## When to Use This Skill

- Get a one-shot snapshot (`overview` / `realm_info` / `user_count`)
- Triage a login-failure or lockout storm (`login_failure_rca`) → cause + action
- Run an access re-certification (`stale_access_audit`: idle users,
  never-logged-in accounts, service-account misuse, orphaned sessions)
- Audit OAuth clients (`client_misconfig_audit`: redirect URIs, PKCE, implicit
  flow, password grant) and fix them (`update_client_redirect_uris`)
- Measure and close the MFA gap (`mfa_coverage_analysis`, `user_credentials`)
- Contain a compromised account (`disable_user` + `revoke_user_sessions` +
  `require_password_reset`, all governed; re-enable needs an approver)
- Rotate a leaked client secret (`rotate_client_secret`, high risk, masked)

**Do NOT use when** the target is not a Keycloak/authentik IdP — route
hypervisor, storage, backup, cluster, network/firewall, database, endpoint, or
OT/industrial work to the appropriate other AIops-tools skill. Cloud IdPs
(Okta, Entra ID, Auth0) are out of scope.

## Related Skills — Skill Routing

| If the user wants… | Use |
|--------------------|-----|
| Keycloak / authentik identity ops | **identity-aiops** (this skill) |
| A non-identity platform (hypervisor, storage, backup, cluster, network device/controller, firewall, database, containers, endpoints, local LLM governance, compliance evidence) | the appropriate **other AIops-tools** skill (proxmox-aiops, truenas-aiops, ceph-aiops, veeam-aiops, k8s-aiops, network-aiops, fabric-aiops, firewall-aiops, postgres-aiops, container-host-aiops, endpoint-aiops, ai-guardian, compliance-aiops, …) |
| Cloud IdPs (Okta, Entra ID, Auth0) | out of scope for this tool |

## Common Workflows

### Login-failure / lockout storm

1. `identity_overview` → how big is the failed-login feed right now?
2. `login_failure_rca` → findings ranked with numbers: spray from one IP,
   targeted brute-force on one account, a client failing with credential
   errors (rotated secret not deployed), an expiry storm, or a lockout storm
3. Contain: `disable_user` + `revoke_user_sessions` (governed, undo/priorState),
   check `user_lockout_status` before unlocking anyone

### Access re-certification

1. `stale_access_audit --stale-days 90` → idle users (with day counts),
   never-logged-in accounts, interactive service accounts, orphaned sessions
2. Confirm with owners, then `disable_user` (reversible, undo-recorded) and
   `revoke_user_sessions` for the orphans

### OAuth client hardening

1. `client_misconfig_audit` → per-client riskScore with evidence
   (wildcard/http redirect URIs, public client with secret, implicit flow,
   missing PKCE, password grant)
2. `update_client_redirect_uris <id> --uri https://... --dry-run` → preview,
   then re-run confirmed (high risk: set `IDENTITY_AUDIT_APPROVED_BY` +
   `IDENTITY_AUDIT_RATIONALE`); the prior list is captured for undo
3. If a secret leaked: `rotate_client_secret` (masked priorState) and update
   the deployments

### MFA rollout tracking

1. `mfa_coverage_analysis` → coverage %, worst groups first, gap list
2. `user_credentials <id>` → what a specific user has configured
3. `require_password_reset` where step-up is part of the rollout

## Governance & Safety

- Every tool is audited to `~/.identity-aiops/audit.db` (relocatable via
  `IDENTITY_AIOPS_HOME`).
- **Secure by default**: with no `~/.identity-aiops/rules.yaml`, high-risk
  operations are denied unless `IDENTITY_AUDIT_APPROVED_BY` names an approver
  (set `IDENTITY_AUDIT_RATIONALE` too). `identity-aiops init` seeds a starter
  rules.yaml; an operator-authored rules file is honoured as-is.
- High-risk ops (`enable_user`, `update_client_redirect_uris`,
  `rotate_client_secret`) require the named approver; writes support
  `--dry-run` and double confirmation at the CLI.
- Reversible writes capture the real fetched before-state and record an
  inverse descriptor (disable↔enable, reset-flag→clear, redirect-URI list
  replay). `revoke_user_sessions` and `rotate_client_secret` are irreversible
  (priorState only; secrets recorded masked).

## References

- `references/capabilities.md` — full tool + platform + API-path reference
- `references/cli-reference.md` — CLI command reference
- `references/setup-guide.md` — onboarding, credentials, and connectivity
