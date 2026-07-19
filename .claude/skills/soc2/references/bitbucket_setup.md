# Bitbucket Setup

## Currently configured: a dedicated Atlassian account token (Basic auth)

`secrets/id-atlassian-bitbucket-token.txt` + `bitbucket.account_email` (the account's email, set inline in `secrets/soc2.config.private.yaml`, itself gitignored - a real identity, not a generic setting, shared with the gsuite/confluence delegated admin since it's the same person), `auth_mode: basic_email`. This replaced an earlier workspace-scoped Bearer access token (`secrets/bitbucket-token.txt`).

**Before switching, every existing check was tested against both tokens side by side** (same repos, same endpoints) to confirm no regression: identical results everywhere, plus one genuine improvement - Account SSH Keys, previously blocked outright for Bearer auth (not a scope gap, a hard restriction on that auth mechanism), now returns real data under Basic auth.

## Token type is ambiguous from the raw string alone

A Bitbucket credential dropped into `secrets/bitbucket-token.txt`-style files could be either:

1. A **workspace/repository/project access token** — used as `Authorization: Bearer <token>`.
2. An **Atlassian account API token** (format `ATATT3xFfGF0...`) — used as HTTP Basic auth with the account's email address as the username and the token as the password.

`bitbucket.auth_mode: auto` runs a tiered probe in `providers/bitbucket_scanner.py::detect_auth_mode`:

1. `GET /2.0/workspaces` with `Authorization: Bearer <token>` → HTTP 200 confirms Bearer mode.
2. On 401/403, and if an account email is configured (see below), retry `GET /2.0/user` with HTTP Basic (email + token) → HTTP 200 confirms Basic+email mode.
3. If both fail and `bitbucket.workspaces` lists specific workspaces, probe `GET /2.0/workspaces/{workspace}` directly with Bearer auth (covers narrowly-scoped tokens that can't list workspaces or the authenticated user).
4. If everything fails, the scan reports `AUTH_FAILED` with an actionable message — no email is ever guessed.

This project sets `auth_mode` explicitly to `basic_email` rather than relying on the probe, since the token type is already known. The account email is read from `bitbucket.account_email` (a literal set in `secrets/soc2.config.private.yaml`, gitignored - the same value gsuite and confluence use, since it's the same person's identity; `bitbucket.account_email_path` still exists as an alternative if that identity should instead come from its own separate gitignored file) rather than the committed config - not registered as a redaction secret either (it legitimately appears in Bitbucket data itself - repo permissions, SSH key ownership).

`GET /2.0/workspaces` still returns `410 Gone` regardless of token type (Atlassian changelog CHANGE-2770 - broad workspace listing is deprecated entirely, not an auth-mechanism issue) - this is why `bitbucket.workspaces` stays pinned to an explicit workspace slug in `secrets/soc2.config.private.yaml` (gitignored - the actual workspace name is company-specific) rather than left empty for auto-discovery.

## Token scope: what's granted vs. what each check needs

The current token's granted scopes: `read:repository`, `read:permission`, `read:ssh-key`, `read:user`, `read:workspace`, `read:project` - all read-only, no admin scopes.

| Check | Scope required | Granted? |
|---|---|---|
| Repos, projects | `read:repository`, `read:project` | ✅ |
| Repo Permissions | `read:permission` | ✅ |
| Account SSH Keys (workspace's own account) | `read:ssh-key` | ✅ |
| Account SSH Keys (individual members' personal accounts) | N/A - blocked by a different rule entirely | ❌ "You cannot administer personal accounts of other users" - a workspace-level token can't read another individual's personal account settings no matter what scope it holds; this is about account ownership, not a grantable scope |
| Webhooks | `read:webhook` | ❌ Not granted, but addable without any admin privilege - this is the one remaining gap that's a plain read-scope away from closing |
| Deploy Keys, Branch Restrictions | `admin:repository` | ❌ Admin-tier scope, not currently granted |
| Project Access Keys | `admin:project` | ❌ Admin-tier scope, not currently granted |

Every one of the ❌ rows degrades to a recorded skipped-check entry (`errors[]`, with Bitbucket's own error body naming the exact missing scope) rather than a silent zero-results table - see `SKILL.md`'s note on how 403s are surfaced.

## Checks investigated and confirmed not buildable

Two further checks were investigated and confirmed to have no public API at all (same category as Access Tokens - UI-only, not a scope problem):

- **2FA/two-step-verification enforcement** - the workspace object (`GET /2.0/workspaces/{workspace}`) has no field for this, and no dedicated endpoint exists. Confirmed via Atlassian's own community/support docs - "Require two-step verification" is a Premium-plan UI-only setting.
- **IP allowlisting** - `GET /2.0/workspaces/{workspace}/ip-allowlist` 404s with "no API hosted at this URL" (a routing-level 404, not a permission error - confirmed live against this project's token). Atlassian's own Jira backlog (BCLOUD-17275, BCLOUD-22699) confirms this has been requested and explicitly will not be implemented.

Both settings live on the same Workspace Settings > Security > **Access controls** page, already listed in `BITBUCKET_MANUAL_REVIEW_URLS` in `report_writer.py` - no new manual-review URL was needed.

**Merge checks** (required approvals / required passing builds before merge) are *not* a gap - they're already covered by `scan_branch_restrictions`, whose `kind` field includes `require_approvals_to_merge` and `require_passing_build_to_merge` alongside the other branch-restriction kinds.

## Endpoints used

| Check | Endpoint |
|---|---|
| Discover workspaces | `GET /2.0/workspaces` |
| List repos | `GET /2.0/repositories/{workspace}` |
| Repo permissions | `GET /2.0/workspaces/{workspace}/permissions/repositories/{repo_slug}` |
| Deploy keys | `GET /2.0/repositories/{workspace}/{repo_slug}/deploy-keys` |
| Webhooks | `GET /2.0/repositories/{workspace}/{repo_slug}/hooks` |
| Branch restrictions | `GET /2.0/repositories/{workspace}/{repo_slug}/branch-restrictions` |
