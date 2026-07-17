# Identity AIops v0.1.0 — preview

Governed AI-ops for **Keycloak** and **authentik** identity providers for AI
agents, with a built-in governance harness (audit, policy, token/runaway
budget, undo-token recording, graduated risk tiers) and an encrypted credential
store. Standalone — no external skill-family dependency. One MCP server spans
both platforms: a per-target `platform` field selects the API shape, and the
same 27 tools work on Keycloak (admin REST `/admin/realms/{realm}/...`,
client-credentials grant with automatic refresh-on-401) and authentik (API v3
`/api/v3/...`, Bearer token).

> **Not affiliated with, endorsed by, or sponsored by the Keycloak project,
> Red Hat, Authentik Security Inc., or the authentik project.** Keycloak and
> authentik are trademarks of their respective owners.

> **Preview / mock-only.** All behaviour is validated against mocked
> Keycloak/authentik JSON responses; it has **not** been run against a live
> IdP. The concrete REST paths are modelled from each project's public API and
> need live verification. Both platforms are free/self-hostable, so a self-hosted
> lab is the easiest live check — `identity-aiops doctor` is the fastest.

## Highlights

- **27 MCP tools** (21 read, 6 write), every one wrapped with `@governed_tool`:
  - **Realm / system** — `identity_overview`, `realm_info`,
    `list_identity_providers`.
  - **Users / groups** — `list_users`, `user_detail`, `user_count`,
    `user_sessions`, `user_credentials`, `list_groups`, `group_members`,
    `user_lockout_status`.
  - **Events** — `login_events`, `admin_events`.
  - **Clients** — `list_clients`, `client_detail`, `client_sessions`,
    `client_session_stats`.
  - **Writes** — `disable_user`, `revoke_user_sessions`,
    `require_password_reset` (med); `enable_user`,
    `update_client_redirect_uris`, `rotate_client_secret` (**high**).
- **Flagship analyses** (transparent heuristics that show their numbers):
  - `login_failure_rca` — failed-auth events windowed by user/IP/client:
    password spray, targeted brute-force, stale stored credential,
    misconfigured client (rotated secret still deployed), expired-credential
    storm, lockout storm — each with cause + action.
  - `stale_access_audit` — enabled users idle > N days, never-logged-in
    accounts, service accounts used interactively, orphaned sessions.
  - `client_misconfig_audit` — wildcard/plain-http redirect URIs, public
    clients carrying secrets, implicit flow, missing PKCE, password grant —
    ranked per-client riskScore with evidence.
  - `mfa_coverage_analysis` — coverage %, per-group breakdown, gap list.
- **Governed writes** — reversible writes capture the **real fetched
  before-state** and record an undo descriptor (`disable_user` ↔
  `enable_user`; `require_password_reset` undoes via `clear=True`;
  `update_client_redirect_uris` replays the prior list). Irreversible writes
  record priorState only — `rotate_client_secret` stores a **masked**
  fingerprint, never the value. High-risk writes take a `dry_run` preview and
  require an approver.
- **Encrypted secret store** — the Keycloak client secret or authentik API
  token lives encrypted in `~/.identity-aiops/secrets.enc` (Fernet + scrypt),
  never plaintext; legacy `IDENTITY_<TARGET>_SECRET` env fallback. TLS
  verification defaults ON.
- **Secure by default** — with no `rules.yaml`, high-risk writes are denied
  unless `IDENTITY_AUDIT_APPROVED_BY` names an approver; `init` seeds the
  dual-control rule explicitly.

## Install

```bash
uv tool install identity-aiops
identity-aiops init
identity-aiops doctor
```
