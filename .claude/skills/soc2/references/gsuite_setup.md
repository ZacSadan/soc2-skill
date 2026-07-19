# Google Workspace (G Suite) Setup

## This reuses your existing GCP service account - no new credential

Domain-wide delegation is authorized by a service account's **Client ID**, which any existing GCP service account already has. This scanner reuses the exact same `secrets/gcp-service-account.json` key already used for the `gcp:` provider - there is no separate G Suite credential file.

**Tradeoff worth knowing**: reusing the same service account means a single leaked key can read both your GCP project *and* your Workspace user directory, instead of those being two separately-scoped credentials. Given the scope granted here is narrow (see below), that's a reasonable tradeoff, but it is a deliberate one, not a free lunch.

## Setup (the actual steps, in order)

### 1. Enable the Admin SDK API

In the same GCP project the service account lives in: **APIs & Services → Library → search "Admin SDK API" → Enable**. No billing impact.

### 2. Find the service account's Client ID

This is a numeric OAuth Client ID, **not** the service account's email address - the Workspace Admin Console asks for this specific number. Easiest way to get it: it's already embedded in `secrets/gcp-service-account.json` under the `"client_id"` field.

### 3. Authorize domain-wide delegation (requires a Workspace Super Admin)

1. Go to [admin.google.com](https://admin.google.com) → **Security → Access and data control → API controls → Manage Domain Wide Delegation → Add new**.
2. **Client ID**: paste the numeric ID from step 2.
3. **OAuth scopes**: paste all five, comma-delimited:
   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly,
   https://www.googleapis.com/auth/admin.directory.group.readonly,
   https://www.googleapis.com/auth/admin.directory.orgunit.readonly,
   https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,
   https://www.googleapis.com/auth/admin.reports.audit.readonly
   ```
   All five are read-only. `admin.directory.user.readonly` alone already covers the Users/Admin Summary chapters (see field list below); the other four unlock Groups, Org Units, Mobile Devices, and the two Reports-API-derived chapters (Suspicious Login Events, OAuth App Grants).
4. Leave **"Overwrite existing client ID"** unchecked unless the Client ID already has a conflicting entry (it controls whether this submission *replaces* whatever that Client ID was previously authorized for - it does not add to or broaden anything on its own).
5. Click **Authorize**. Propagation is usually within minutes.

### A scope deliberately NOT requested: `admin.directory.user.security`

This looks like the obvious scope for reading OAuth app grants directly off the user resource, but it's **not read-only** - confirmed against Google's own reference docs, it also grants `twoStepVerification.turnOff` (the ability to disable a user's 2FA). Not requested for that reason. OAuth app grant visibility is instead read via the Reports API's `token`/`authorize` activity events (`admin.reports.audit.readonly` - genuinely read-only), which is what `scan_oauth_app_grants` uses.

### 4. Pick who to impersonate

The Admin SDK Directory API requires the delegated credentials to act *as* a real Workspace user with directory-read privilege - there's no "service account acting as itself" option. **What was actually used here**: an existing Super Admin's own email address, not a dedicated custom-role account.

A narrower alternative, if you'd rather not delegate as a full Super Admin: create a **custom admin role** (Account → Admin roles) granting only **Admin API privileges → Users → Read**, assign it to a dedicated account, and impersonate that instead. Functionally equivalent for this scanner's purposes since the OAuth scope is the same either way - the difference is blast radius if the underlying key ever leaks (impersonating a full Super Admin vs. a narrowly-privileged dedicated account). Not required, just an available hardening step.

### 5. Store the delegated email in the private config, not in the committed one

The impersonated user's address is a real person's identity, not a generic setting - it's kept as a literal (`gsuite.delegated_admin_email`) in `secrets/soc2.config.private.yaml` (gitignored) rather than in the committed `config/soc2.config.yaml`. This same value is also used by the Bitbucket scanner's `basic_email` auth mode (`bitbucket.account_email`) and by Confluence (`confluence.account_email`) - one shared identity, not three copies of the same email. `gsuite.delegated_admin_email_path` still exists as an alternative if that identity should instead come from its own separate gitignored file rather than being set inline.

## Verifying the scope is actually read-only

Don't just trust the scope string - OAuth scope enforcement in Google's domain-wide delegation model happens at **token minting**, not just at the API call: a service account can only ever obtain a token for scopes explicitly listed in its Workspace Admin Console delegation entry. Requesting a broader scope in code doesn't help if that broader scope was never authorized for this Client ID.

This was confirmed empirically (not just assumed) by attempting a `users().delete()` call against a deliberately fake, nonexistent email address:

```
status: 403
"Request had insufficient authentication scopes." / reason: insufficientPermissions
```

The 403 (not a 404) confirms the write attempt was rejected at the authorization layer before Google even looked for the target resource - proving the read-only scope genuinely blocks writes, regardless of the fact that the impersonated user is a real Super Admin with full write power through their own login session.

## What one scope gets you

`admin.directory.user.readonly` alone exposes all of the following per user, in the same API response - no additional scope needed for any of it:

| Field | What it's used for |
|---|---|
| `suspended` | Active vs. suspended status |
| `archived` | Archived status |
| `isAdmin` | Super Admin flag |
| `isDelegatedAdmin` | Holds some delegated admin role short of Super Admin |
| `isEnrolledIn2Sv` | Has 2-step verification enrolled at all |
| `isEnforcedIn2Sv` | 2-step verification is enforced (not just enrolled - can differ) |
| `lastLoginTime` | Used to flag active-but-dormant accounts (`stale_login_days` in config, default 180) |
| `orgUnitPath` | Which org unit the user belongs to |

Not available via this scope (would need additional scopes/APIs): recovery email/phone values (present but deliberately not surfaced to avoid handling more PII than needed), password-strength assessment (exists in the Admin Console UI - "Reports → Accounts" - but the exact API field/scope for it wasn't confirmed during this build; would need further verification before adding).

## What the 4 additional scopes get you

| Scope | Chapter | Data |
|---|---|---|
| `admin.directory.group.readonly` | Groups | Every group, direct member count, and - critically - who holds `OWNER`/`MANAGER` role (the group-level equivalent of admin privilege: determines who can add/remove members and change settings, not just who's in the group) |
| `admin.directory.orgunit.readonly` | Org Units | The org unit hierarchy - structural context for interpreting each user's `org_unit_path`, not a findings chapter on its own |
| `admin.directory.device.mobile.readonly` | Mobile Devices | Per-device compromised status, encryption status, screen-lock password status, last sync - flags a real posture problem (compromised device: critical; approved-and-active device with no disk encryption: high; no screen lock: medium) |
| `admin.reports.audit.readonly` | Suspicious Login Events, OAuth App Grants | Login activity filtered to a curated list of genuinely concerning event names (not plain success/failure, which would flood the report - see `CONCERNING_LOGIN_EVENTS` in `gsuite_scanner.py`), and OAuth "authorize" events (which apps were granted access, by whom, what scopes) within `gsuite.audit_lookback_days` (default 30 days) |

**Known false-positive fixed during this build**: `deviceCompromisedStatus` returns different human-readable strings per platform for the "safe" case - `"Undetected"` on Android, `"No compromise detected"` on iOS. An earlier substring-based check (`"compromis" in status`) flagged every iOS device as critical, since "No compromise detected" contains the substring "compromis" despite meaning the opposite. Fixed to an exact match against the literal value `"Compromised"` instead of a substring heuristic - Google's Admin SDK docs don't publish a definitive enum list for this field, so this is deliberately conservative (only fires on the one value confirmed to actually mean compromised) rather than guessing at every possible "bad" phrasing.

## Config

`gsuite.checks.*` toggles each check independently: `users`, `admin_summary`, `groups`, `org_units`, `mobile_devices`, `suspicious_logins`, `oauth_app_grants`. `gsuite.stale_login_days` (default 180) controls the dormant-active-account threshold; `gsuite.audit_lookback_days` (default 30) controls how far back the two Reports-API-derived checks look. Missing `gsuite.delegated_admin_email` (and no `delegated_admin_email_path` file either) is treated as "not configured yet" - the scan skips with a clear message rather than failing, same posture as Trello's missing-credentials handling.
