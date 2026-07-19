<!-- mcp-name: io.github.AIops-tools/identity-aiops -->

# Identity AIops

**Governed AI-ops for self-hosted identity providers — Keycloak + authentik.**

`identity-aiops` gives AI agents (and the humans supervising them) a safe,
audited way to operate the identity plane of self-built and small/mid-size
infrastructure: who can sign in, what failed and why, which OAuth clients are
misconfigured, and who still has no second factor. It is built for teams
running their own Keycloak or authentik who want agent-driven identity
operations **with receipts** — every tool call is audited, writes carry risk
tiers with dry-run previews and undo tokens, and high-risk actions require a
named human approver.

> **Verification status**: modelled on the public Keycloak admin REST API and
> authentik API v3 and exercised against mocked responses; there is no recorded
> end-to-end run against a live instance yet. `identity-aiops doctor` is the
> fastest live check — see [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## What it does

| Area | Tools |
|------|-------|
| Realm / system | overview, realm settings (brute-force protection, password/OTP policy), identity providers |
| Users | list/search, detail, count, sessions, credentials (MFA surface), groups, members, lockout status |
| Events | authentication events, admin/config-change events |
| Clients | list, detail, per-client sessions, session stats |
| **Flagship RCA** | `login_failure_rca` — brute-force (spray/targeted) vs misconfigured client vs expired-credential storm vs lockout storm; `stale_access_audit` — dormant users, never-logged-in accounts, service accounts used interactively, orphaned sessions; `client_misconfig_audit` — wildcard/http redirect URIs, public clients with secrets, implicit flow, missing PKCE, password grant (ranked risk); `mfa_coverage_analysis` — coverage %, gap list |
| Governed writes | `disable_user` / `enable_user` (undo pair), `revoke_user_sessions`, `require_password_reset` (undo clears the flag), `update_client_redirect_uris` (undo replays the prior list), `rotate_client_secret` (masked priorState) |

29 MCP tools: 21 reads (including the 4 analyses) + 6 governed writes + 2 undo
tools (`undo_list`, `undo_apply`). The
same tools work on both platforms — a per-target `platform` field selects the
API shape (auth flow + resource paths).

## Supported platforms

| Platform | API | Auth |
|----------|-----|------|
| **keycloak** | Admin REST API (`/admin/realms/{realm}/...`) | OAuth2 client-credentials grant against `/realms/{realm}/protocol/openid-connect/token`; short-lived token auto-refreshed on 401 |
| **authentik** | API v3 (`/api/v3/...`) | Long-lived API token (Bearer) |

Platform notes: `require_password_reset`, `rotate_client_secret`,
`client_sessions`, `client_session_stats`, and `user_lockout_status` are
Keycloak-shaped (authentik has no equivalent endpoint — the tools return a
teaching error there). authentik contributes the global session list used by
the stale-access audit's orphaned-session check.

Missing a platform (Authelia, Zitadel, Ory...), an endpoint, or an analysis
you need? **缺功能提 issue/PR 欢迎留言** — open an issue or PR at
https://github.com/AIops-tools/Identity-AIops, feature requests welcome.

## Security: read-only mode

This tool is meant to be handed to an AI agent, so its safety story is enforced
by the server rather than requested in a prompt:

```bash
export IDENTITY_READ_ONLY=1
```

With that set, the **7 write tools are never registered**. An MCP client
lists **22 tools instead of 29** — the writes are not hidden, not
gated behind a flag, and not merely refused when called. They are absent from
the session. A model cannot invoke a tool it was never offered, and cannot be
argued into one.

That distinction is the whole point. A tool that exists but refuses still invites
retry loops and "I'll describe the call instead" behaviour from smaller models,
and it leaves a reviewer trusting a promise. An absent tool is a fact you can
check: connect, list the tools, and see that the writes are not there.

Enforcement is two layers deep, so the switch cannot be sidestepped by changing
entry point:

| Layer | What it does | Covers |
|---|---|---|
| `@governed_tool` harness | refuses every non-read operation outright | MCP, CLI, and in-process callers |
| MCP registration | write tools are removed from `list_tools()` | anything speaking MCP |

Read operations are unaffected, and every call is still audited to
`~/.identity-aiops/audit.db`.

> The read/write split is derived from each tool's declared `risk_level`, and a
> test asserts that this never disagrees with the `[READ]`/`[WRITE]` tag in the
> tool's own documentation — so a write can't quietly present itself as a read.

Running a smaller / local model? See
[agent-guardrails.md](skills/identity-aiops/references/agent-guardrails.md) — it lists
the guardrails this tool now enforces for you (so you don't spend prompt budget
restating them) and gives a ready-made system prompt for what's left.

## Quick start

```bash
uv tool install identity-aiops        # or: pipx install identity-aiops

identity-aiops init      # wizard: target + realm + credential (encrypted) + policy seed
identity-aiops doctor    # token acquisition + user-count probe per target
identity-aiops overview  # one-shot estate summary
```

For Keycloak, create a **confidential client** with *Service accounts roles*
enabled and grant its service account the realm-management roles you want the
agent to have (start with `view-users`, `view-events`, `view-clients`; add
`manage-users` / `manage-clients` only if you want the governed writes). For
authentik, create an API token for a (least-privileged) admin user.

CLI surface: `users` (list/show/sessions/credentials + disable/enable/
revoke-sessions/require-reset), `clients` (list/show + set-redirect-uris/
rotate-secret), `events`, `overview`, `doctor`, `secret`, `init`, `mcp`.
Write commands take `--dry-run` and always double-confirm; execution is
delegated to the governed MCP twins so CLI writes land in the audit log too.

## MCP configuration

```json
{
  "mcpServers": {
    "identity-aiops": {
      "command": "uvx",
      "args": ["--from", "identity-aiops", "identity-aiops-mcp"],
      "env": {
        "IDENTITY_AIOPS_MASTER_PASSWORD": "<master password for secrets.enc>"
      }
    }
  }
}
```

> **env-block caveat**: MCP clients launch the server with a minimal
> environment — variables from your shell profile are NOT inherited. Anything
> the server needs (`IDENTITY_AIOPS_MASTER_PASSWORD`, an alternate
> `IDENTITY_AIOPS_HOME`, `IDENTITY_AUDIT_APPROVED_BY` for high-risk writes)
> must be set in the `env` block above.

## Governance

Every MCP tool runs through the vendored governance harness
(`identity_aiops/governance/`, zero external dependencies):

- **Audit** — every call (including denials and errors) lands in
  `~/.identity-aiops/audit.db` with params, status, risk level, and approver.
- **Budget** — per-session call/time budgets and a runaway breaker
  (`IDENTITY_MAX_TOOL_CALLS`, `IDENTITY_MAX_TOOL_SECONDS`,
  `IDENTITY_RUNAWAY_MAX`).
- **Risk tiers + approval** — reads are `low`; containment/hygiene writes
  (`disable_user`, `revoke_user_sessions`, `require_password_reset`) are
  `medium`; access-granting or boundary-replacing writes (`enable_user`,
  `update_client_redirect_uris`, `rotate_client_secret`) are `high`.
  **Secure by default**: with no `rules.yaml`, high/critical writes are denied
  unless a named approver is present (`IDENTITY_AUDIT_APPROVED_BY`, plus
  `IDENTITY_AUDIT_RATIONALE`). `identity-aiops init` seeds this dual-control
  rule explicitly; the file hot-reloads.
- **Undo** — reversible writes capture the REAL prior state (fetched before
  mutating, never guessed) and record a replayable inverse descriptor in
  `~/.identity-aiops/undo.db`. Irreversible writes (`revoke_user_sessions`,
  `rotate_client_secret`) record priorState only — the secret is stored
  **masked**, never in clear.
- **Sanitize** — every string an IdP returns is folded through an
  injection-safe normaliser (bounded length, control characters stripped)
  before an agent sees it.
- **Secrets** — credentials live Fernet-encrypted (scrypt-derived key) in
  `~/.identity-aiops/secrets.enc`, never plaintext on disk; a legacy
  `IDENTITY_<TARGET>_SECRET` env var is honoured as fallback and
  `identity-aiops secret migrate` moves it in. TLS verification defaults ON.

## Configuration

`~/.identity-aiops/config.yaml` (created by `init`):

```yaml
targets:
  - name: sso1
    platform: keycloak
    base_url: https://sso.example.com
    realm: master
    username: identity-aiops-agent   # the confidential client's client_id
    verify_ssl: true
  - name: ak1
    platform: authentik
    base_url: https://auth.example.com
    verify_ssl: true
```

Set `IDENTITY_AIOPS_HOME` to relocate all state (config, secrets, audit,
undo, policy). `IDENTITY_AIOPS_CONFIG` points the MCP server at an alternate
config file.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check .
```

MIT License. Part of the [AIops-tools](https://github.com/AIops-tools) line —
governed AI-ops tooling for self-hosted infrastructure.
