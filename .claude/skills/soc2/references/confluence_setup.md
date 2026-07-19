# Confluence Setup

## Credentials

Same Atlassian auth model as Bitbucket: HTTP Basic auth with an account email + a scoped API token (`ATATT3xFfGF0...` format, created at `id.atlassian.com/manage-profile/security/api-tokens`).

- `secrets/id-atlassian-confluence-token.txt` — the scoped API token, created with read-only scopes (`read:space:confluence`, `read:space.permission:confluence`, `read:permission:confluence`, `read:group:confluence`, `read:confluence-content.permission`, `read:content.permission:confluence`, `read:content.restriction:confluence`, and others - the full granted set covers spaces, space/content permissions, groups, users, audit log, and configuration).
- `confluence.account_email` — the account's email, set inline in `secrets/soc2.config.private.yaml` (gitignored), the same value already used by Bitbucket (`bitbucket.account_email`) and Google Workspace (`gsuite.delegated_admin_email`) - one identity, one value, not three copies of the same email. `confluence.account_email_path` still exists as an alternative if that identity should instead come from its own separate gitignored file.

## Requests go through Atlassian's centralized API gateway, not the site's own domain

This was the hard part to discover. This site's own domain (a legacy `.jira.com` Atlassian hostname predating a company rebrand - the actual hostname is company-specific, kept out of this doc) rejects direct API requests with a raw, non-JSON `401 Unauthorized` (a plain Tomcat error page, not Atlassian's usual JSON error body) - confirmed live this is unrelated to credentials or scope. Following the site's own unauthenticated redirect chain (`GET /wiki` with no auth) revealed it's fronted by an SSO-enforcement proxy that redirects everything, including API calls, through `id.atlassian.com` login - which blocks direct API token auth against the raw domain.

The redirect chain also revealed the site's **cloud ID** (embedded in the ARI in the redirect URL: `ari:cloud:confluence::site/{cloud_id}`). Requests through Atlassian's centralized gateway instead - `https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/rest/api/...` - work cleanly with the same Basic-auth credentials. This is the same gateway pattern OAuth 3LO apps normally use; it turns out to also work for plain API-token Basic auth, at least for this site's configuration.

The `cloud_id` is stored in `secrets/soc2.config.private.yaml` (`confluence.cloud_id`) rather than the committed config, since it identifies the specific company site.

## What's scanned

**Spaces** (`scan_spaces`, or `scan_main_space` when `confluence.main_space` is configured - see Config below) - each space gets:
- **Anonymous access** - flags any space where any permission entry has `anonymousAccess: true` (the Confluence analog of a public bucket/repo) as `critical`. Confirmed live across a sample that this is currently `false` everywhere in this instance - a genuinely clean result, not an unverified assumption.
- **Admins** - who holds the `administer` operation on the space (both individual users and groups), covering real users, Atlassian Marketplace app integrations (Slack, Google Drive Connector, etc. - these show up as "admins" too since apps can hold space permissions), and groups (prefixed `group:`).

**Space Permissions** (`confluence.space_permission`, only produced when `main_space` is configured) - every real user who can reach the main space, whether granted directly or via a group they belong to, each row listing the full set of operations they hold and a `via` column showing the source(s) (`direct`, or one or more `group:name` entries) - any `administer:*` operation is bolded red in the Markdown report. The report splits this into two chapters - **"Space Permissions - group:administrators"** (anyone whose access comes via the site-wide `administrators` or `wiki-admin` groups) and **"Space Permissions - Other"** (everyone else), "Other" listed first - and within each, deactivated users (subject name contains `(Deactivated)`) are put in their own gray-boxed subsection at the end rather than mixed in with active users, with the rest sorted by their operations set.

**Operations are kept at full `operation:targetType` granularity, not collapsed to the operation name alone.** Confluence grants `create`/`delete`/`archive`/`export`/`restrict_content` separately per content type - a real space had 14 distinct `(operation, targetType)` pairs live, e.g. `create:page`, `create:comment`, `create:attachment`, `create:blogpost` are four separate grants, and `delete` similarly splits across `attachment`/`blogpost`/`comment`/`page`/`space`. An earlier version of this scanner stored only the bare operation name (`"create"`), which silently merged all four `create:*` grants into one bucket and lost exactly which content types a subject could act on - a real loss of signal for a permissions audit, caught when the user pointed out granted permissions weren't showing up distinctly. `admin`-equivalence checks (severity, the `admin` tag, the space's `admins` list) still key off the operation name alone (`administer`) via `_has_admin_op()`, since target type doesn't change whether a grant is admin-equivalent.

**Group grants are resolved to real members, not left opaque.** A space permission entry granted to a group (e.g. `group:confluence-users`, `group:administrators`) is expanded via the group-membership API (`GET /wiki/rest/api/group/{id}/membersByGroupId` - the by-name `/group/{name}/member` endpoint 401s with "scope does not match" under this token's granted scopes, confirmed live) into its actual member accounts, which are merged into the same per-user rows as directly-granted users. A group whose id can't be resolved (name not found in the site's group directory) or whose member list fails to load falls back to its original opaque `group:name` row instead of silently disappearing.

**Known bug found and fixed during this build**: the admin-operation name was initially guessed as `"admin"` or `"setspacepermissions"` - neither matches Confluence's real API, which uses `"administer"` (targeting `"space"`). The wrong guess silently produced zero admins across all 1,533 spaces rather than erroring, which is why it was caught by noticing an implausible "Admins: none" on every single space rather than a thrown exception - worth remembering that a silently-wrong filter is easier to miss than a crash.

**Worth a manual look, not currently flagged automatically**: several space admins are tagged `(Deactivated)` or `(Unlicensed)` in the raw Confluence data (e.g. a departed employee still listed as a space administrator) - a real access-hygiene finding surfaced by this scan, not yet turned into its own severity-escalated check.

## Not yet built

- **Global (site-wide) permissions** - who can create spaces at the site level, separate from per-space permissions.
- **Content/page-level restrictions** - `read:content.restriction:confluence` is already granted, but per-page restriction scanning would mean iterating every page in every space (a much larger volume than the 1,533 spaces themselves) - not attempted in this first pass.
- **Installed Marketplace apps as their own inventory** - currently only visible incidentally as space admins/permission subjects, not listed as a standalone chapter.

## Config

`confluence.checks.spaces` toggles the one current check. Missing `secrets/id-atlassian-confluence-token.txt` is treated as "not configured yet" - skips with a clear message rather than failing, same posture as every other optional provider.

`confluence.main_space` (set in `secrets/soc2.config.private.yaml`, e.g. `main_space: "PRD"`) narrows the scan to one space of real interest instead of all 1,500+ spaces this account can see:
- The main space still gets its own `confluence.space` summary row (anonymous access, admin list) exactly as before.
- Every user/group with a permission grant on the main space gets a `confluence.space_permission` row listing all operations they hold - a full permission breakdown, not just admins.
- The other spaces are NOT enumerated or fetched in detail (still cheaply paginated once, key-only, to get a count) - instead a single `confluence.other_spaces_summary` note reports how many other spaces exist ("Detected another N authorized space(s) under this account").
- Leaving `main_space` unset falls back to the original behavior: every space listed with its own anonymous-access/admins row (no per-user breakdown, no "other spaces" note).
