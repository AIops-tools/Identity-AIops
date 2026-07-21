# Changelog

## v0.4.0 — 2026-07-21

### Changed (BREAKING)
- **Removed the authorization layer** — read-only mode, the approver gate, and rules.yaml deny are gone. The skill no longer decides read vs write; that is the agent's judgement or the connecting account's permissions. `<PREFIX>_READ_ONLY` now has no effect (a startup warning is logged); `<PREFIX>_AUDIT_APPROVED_BY`/`_RATIONALE` are optional audit annotations.
- The retained guarantee is **unbypassable audit over MCP and CLI alike** — no unaudited entry point. Harness = audit + runaway safety guard + undo + sanitize; `risk_level` is a descriptive audit label, not a gate.

See RELEASE_NOTES.md for tool-specific changes.


## v0.3.0 — 2026-07-20

### Fixed
- **`rotate_client_secret` can no longer rotate the client this tool authenticates as.** Keycloak auth here is `client_credentials` using the configured client id and secret, so rotating that client invalidated the stored credential on the spot — and this operation is irreversible by design, so there was not even a failed undo to notice.
- `disable_user`'s existing guard now also runs on the `dry_run` path, where it was being skipped entirely..
- Harness: a write whose response is lost is audited `status=unknown`, not `error` — it may have taken effect. Undo tokens gain `effectVerified` (undo.db migrated in place).
- Harness: a dry-run no longer records an undo token, and no longer requires a named approver. Guards now run on the preview path.
- Truncated strings end in an ellipsis instead of being cut silently; error messages are capped at 800 chars, not 300.

See RELEASE_NOTES.md for the full detail.

## v0.1.1 — 2026-07-17

### Fixed
- Added the MCP Registry ownership marker (mcp-name) to the README so the server publishes to the MCP Registry.

## v0.1.0 — 2026-07-17

Initial preview release.

- **27 MCP tools** (21 read incl. 4 flagship analyses, 6 governed writes) across
  **Keycloak** (admin REST API, client-credentials grant with refresh-on-401)
  and **authentik** (API v3, Bearer token), selected per target by a
  name-keyed platform registry.
- **Flagship analyses**: `login_failure_rca` (password spray / targeted
  brute-force / stale stored credential / misconfigured client /
  expired-credential storm / lockout storm), `stale_access_audit` (idle users,
  never-logged-in accounts, interactive service accounts, orphaned sessions),
  `client_misconfig_audit` (wildcard/http redirect URIs, public clients with
  secrets, implicit flow, missing PKCE, password grant — ranked riskScore),
  `mfa_coverage_analysis` (overall + per-group coverage %, gap list).
- **Governed writes** with dry-run previews, fetched prior state, and undo where
  reversible: `disable_user` / `enable_user` (undo pair),
  `revoke_user_sessions` (priorState session count, no undo),
  `require_password_reset` (undo clears the flag via `clear=True`),
  `update_client_redirect_uris` (undo replays the prior list),
  `rotate_client_secret` (masked priorState, no undo).
- **Secure by default**: with no `rules.yaml`, high-risk writes require a named
  approver (`IDENTITY_AUDIT_APPROVED_BY`); `init` seeds a dual-control starter
  rules file (never clobbers an operator-authored one).
- **Encrypted secret store** (`secrets.enc`, Fernet + scrypt); TLS verification
  defaults ON; central percent-encoding of every URL path segment.
- Vendored governance harness (audit / budget / risk tiers / undo / sanitize) —
  zero external skill-family dependencies.
- Preview / mock-only: modelled on the public Keycloak and authentik APIs,
  validated against mocked responses; `identity-aiops doctor` (token
  acquisition + user-count probe) is the fastest live check.
