# Changelog

## v0.8.0 — 2026-09-12

### Added
- **Installable as a Claude Code plugin.** `.claude-plugin/plugin.json` plus a
  root `.mcp.json` make this repo a plugin, so `/plugin install identity-aiops@aiops-tools`
  delivers the skill and registers the MCP server in one step. The server is
  pinned to the exact package version the manifest declares, so an audit row
  stays traceable to the code that produced it. Nothing about the tool itself
  changed — the CLI and the standalone MCP server work exactly as before.
- **Installable from ClawHub as an OpenClaw bundle plugin** (`@aiops-tools/identity-aiops`): one install delivers the skill *and* its MCP
  server, pinned to this exact release. `clawhub.ai/plugins`.

### Fixed
- **The skill was invisible to the model in OpenClaw.** Its metadata
  declared `requires.config` (OpenClaw reads that as config *keys*, not file
  paths, so it can never be satisfied), `requires.env` and `requires.bins`
  naming our own CLI — which a plugin user never has on PATH — plus a
  `primaryEnv` that turned a config path into an API-key prompt. Measured on
  OpenClaw 2026.6.35: `Visible to model: no`. It now requires
  `anyBins: [identity-aiops, uvx]` — either one suffices — with every variable kept
  in `optional.env` (still declared, no longer a load gate), which the same
  command reports as `Visible to model: yes`.
## v0.7.0 — 2026-08-10

### Fixed
- **An undetermined outcome no longer exits as a plain failure.** A write whose response was lost carries *both* `error` and `outcomeUnknown`, and the harness deliberately judges unknown first when writing the audit row — the change may have taken effect, so a blind retry could apply it twice. The CLI guard judged `error` first, so the audit said "may have taken effect" while the exit status told a script it had not happened. The two layers now agree (exit 2, not 1), and a test pins the ordering so it cannot silently flip back.
- **Timestamp rendering cannot crash a listing.** `fromtimestamp` raises for values outside the platform's time range, so one absurd epoch from the server would have taken down a whole users/sessions/events read instead of leaving that single field unknown; and a bool is not a timestamp (`bool` subclasses `int`, so `True` rendered as one second past the epoch). Both are now `null`.
- **The CLI reported a refused or failed write as a success.** Every governed write printed the twin's payload and exited **0** whatever it said, so the self-lockout refusal of `rotate-secret` — and a write against a user that does not exist — were indistinguishable from a landed change to a `&&` chain or a CI job. The dry-run path already exited 1, which made it worse: the preview was stricter than the write it previews. All seven call sites now route through a `checked()` helper that exits 1 on `{"error": ...}` and 2 on an undetermined outcome. Caught on a live Keycloak 26.0; an invariant test now fails if any future CLI command prints a governed result unchecked.
- **Timestamps render as ISO-8601 UTC on both platforms.** `created`, `lastLogin`, session `started` / `lastAccess` and event `time` were passed through exactly as the identity provider sent them — Keycloak epoch-**milliseconds** as a string of digits (`"1786335328000"`), authentik ISO-8601 — so one field name carried two incompatible formats depending on the target, and on Keycloak it was not something a consumer could subtract from `now` without knowing both the platform and the unit. This tool exists to span a mixed estate, so the read surface now normalises; a missing value stays `null` rather than becoming the epoch. Found on a live Keycloak 26.0 realm.

## v0.6.0 — 2026-08-03

### Fixed
- **`undo apply` replays against the target the original write ran on.** It dispatched the inverse against whatever target the *caller* named — in practice the config's first entry — while the write's own target sat unused in the undo record. On a multi-target config the inverse therefore ran against the wrong host; it only looks harmless because the resource usually is not there, but two hosts holding the same name and the inverse **succeeds on the wrong one, silently**. An explicitly named target still wins. Line-wide: all 24 copies had the identical defect. Caught live in container-host-aiops, where a stop recorded against a Podman target replayed against a Portainer one.

## v0.5.0 — 2026-08-02

### Changed (BREAKING)
- **Requires MCP SDK 2.0** (`mcp[cli]>=2.0,<3.0`). `mcp.server.fastmcp` no longer exists in 2.0; the server is now built with `MCPServer` and reports its package version in the stdio handshake.

### Fixed
- **`undo apply` works from the CLI.** Every write tool is imported lazily inside its own CLI command, so a CLI-driven undo ran in a process where the inverse tool was never registered and failed with "inverse tool is not registered" — for every write tool. Only the MCP entry point, which imports the whole server, worked. Found while live-verifying against a real cluster.
- **An undetermined outcome is audited `unknown`, not `ok`.** The harness only classified a result as undetermined when the payload *also* carried an `error` key, so a write that looked successful but had not been confirmed was recorded as a success.


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
