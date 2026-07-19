# SOC2 Security Scanner

A Claude Code skill that audits the security posture of **GCP, Bitbucket, Trello, AWS, Google Workspace, and Confluence**, and produces evidence suitable for SOC2 compliance reviews. Every run prints a console summary, saves a timestamped JSON snapshot per provider, diffs against the previous snapshot, and writes a Markdown report you can paste into tickets or a compliance evidence folder. Every credential it uses is strictly **read-only** by design (see [Security notes](#security-notes)) — **it cannot modify, delete, or otherwise write to any of the connected SaaS services**.

The scanner and all its logic live under [`.claude/skills/soc2/`](.claude/skills/soc2/) as a self-contained Claude Code skill — this repo is a working install of that skill plus its config and (gitignored) credentials.

## What it checks

| Provider | Highlights |
|---|---|
| **GCP** | IAM service accounts/keys, project IAM bindings (with custom-role permissions expanded), firewall rules, SSH key metadata, API keys, Security Command Center, IAM Recommender, Cloud Asset public IAM bindings, KMS key rotation, Cloud SQL exposure, Secret Manager rotation, Logging sinks, Artifact Registry, Pub/Sub, GKE cluster hardening, Cloud DNS, Storage bucket config, Org Policy constraints |
| **AWS** | Root account MFA/keys, IAM users/keys/roles/bindings, IAM Access Advisor, password policy, security groups, EC2 key pairs, EBS default encryption, VPC Flow Logs, S3 public exposure, API Gateway keys, CloudTrail, AWS Config, KMS key rotation, RDS exposure, Resource Explorer inventory, Security Hub/GuardDuty/Access Analyzer |
| **Bitbucket** | Repos, per-repo access levels, deploy keys, project access keys, account SSH keys, webhooks, branch restrictions (incl. merge checks) |
| **Trello** | Organization-level membership (admin/normal, deactivated/unconfirmed accounts), boards (visibility, staleness), board members grouped by member with every board + permission level nested underneath |
| **Google Workspace** | User directory via domain-wide delegation (reuses the GCP service account, no new credential): suspended/admin/2FA status, dormant-but-active accounts, super-admin-count summary; groups, org units, mobile device posture; Reports-API-derived Suspicious Login Events and OAuth App Grants |
| **Confluence** | Space permissions with full operation-level granularity (e.g. `create:page` vs `create:comment`, not just `create`), group grants resolved to real member accounts (not left as an opaque group name), anonymous/public access flagged critical. Can be narrowed to one `main_space` of interest instead of enumerating a whole 1000+-space fleet |

Every check is independently fault-tolerant — a missing permission or disabled API degrades that one check to a "skipped" entry in the report instead of crashing the whole scan. See [`SKILL.md`](.claude/skills/soc2/SKILL.md) for the full, current list of checks and how the report is organized.

A few report-quality details worth knowing about since they aren't obvious from a quick look:

- **Identity grouping uses the provider's real unique ID, never a display name.** Trello's `full_name` in particular is free-text with no uniqueness constraint - this workspace has multiple distinct accounts sharing a display name , so grouping by name alone would silently merge unrelated accounts' access into one row. Each member's own username is shown alongside their name to disambiguate, and near-namesakes differing only in case/punctuation still sort next to each other.
- **Staleness and privilege are color-coded in the Markdown report**, not just left as plain values: stale passwords/keys/activity dates (context-dependent thresholds - 90/180 days for keys, 6 months for AWS console passwords, 3 months for Trello activity) render red; `admin`-level permissions render red; closed/archived/disabled resources render on a gray background.
- **Large, low-signal fleets of near-duplicate resources can be folded into a collapsible section** in the Markdown report (any chapter can declare `collapsible_groups`) so hundreds of same-pattern resources (e.g. per-customer storage buckets) don't drown out the handful of genuinely distinct ones - the full detail is still there, just collapsed by default.
- **Confluence's group grants are resolved to real member accounts**, not left as an opaque `group:administrators` placeholder — the report shows exactly who inherits access and through which group(s), with deactivated users set apart in their own grayed-out, severity-muted subsection rather than mixed in with active accounts.

## Quick start

1. **Install dependencies:**
   ```
   pip install -r .claude/skills/soc2/scripts/requirements.txt
   ```

2. **Add credentials** under `secrets/` at the repo root (gitignored, never committed):
   - `secrets/gcp-service-account.json` — GCP service-account key ([setup](.claude/skills/soc2/references/gcp_setup.md)) — also reused by Google Workspace's domain-wide delegation, no separate key needed
   - `secrets/id-atlassian-bitbucket-token.txt` — Bitbucket API token ([setup](.claude/skills/soc2/references/bitbucket_setup.md))
   - `secrets/id-atlassian-confluence-token.txt` — Confluence API token, same Atlassian account family as Bitbucket ([setup](.claude/skills/soc2/references/confluence_setup.md))
   - `secrets/trello-credentials.json` — `{"api_key": "...", "token": "..."}` ([setup](.claude/skills/soc2/references/trello_setup.md))
   - `secrets/aws-access-keys.csv` — CSV from IAM > Users > Security credentials > Create access key ([setup](.claude/skills/soc2/references/aws_setup.md))
   - `secrets/soc2.config.private.yaml` — company-identifying values that shouldn't be in the committed config (workspace names, hardcoded manual-review URLs, name-highlight patterns, and the shared delegated-admin email used inline by `gsuite.delegated_admin_email`/`bitbucket.account_email`/`confluence.account_email` — one identity, one value, not three copies). Deep-merged onto `config/soc2.config.yaml` at load time; see [field-by-field breakdown below](#secretssoc2configprivateyaml-fields).

   All six providers use read-only credentials by design (GCP viewer-tier IAM roles, AWS's `SecurityAudit` managed policy, scoped Bitbucket/Confluence tokens, a domain-wide-delegation scope set that was empirically confirmed to reject write calls) — the scanner never needs write access to do its job.

3. **Review non-secret settings** in [`config/soc2.config.yaml`](config/soc2.config.yaml): which GCP projects/Bitbucket workspaces/AWS region to scan, per-check on/off flags, and severity thresholds.

4. **(GCP only) Run the permission pre-flight probe** so missing permissions or disabled APIs show up as a clear table instead of a crash mid-scan:
   ```
   python .claude/skills/soc2/scripts/check_permissions.py
   ```

5. **Run a scan:**
   ```
   python .claude/skills/soc2/scripts/soc2_scan.py --scope all         # everything
   python .claude/skills/soc2/scripts/soc2_scan.py --scope gcp         # one provider at a time
   ```

   Provider names for `--scope`: `gcp`, `bitbucket`, `trello`, `aws`, `gsuite`, `confluence`, or `all`. Useful flags: `--no-diff` (skip comparing against the previous snapshot), `--no-report` (skip the Markdown report), `--json-only` (snapshots only, no console/report output), `--config <path>` (use an alternate config file). The process exits nonzero if any `critical`/`high` finding is present — useful for CI gating.

## Output

- **Console** — fixed provider order (GCP → Bitbucket → Trello → AWS → Google Workspace → Confluence), organized into per-resource-type chapters rather than one flat list.
- **JSON snapshots** — `.state/snapshots/<provider>/<provider>-<timestamp>.json`, one per provider per run, diffed against that provider's own most recent prior snapshot. Schema documented in [`snapshot_schema.md`](.claude/skills/soc2/references/snapshot_schema.md).
- **Markdown report** — `reports/soc2-report-<scope>-<timestamp>.md`: executive summary, a table of contents, per-provider chapters, and a diff-since-last-scan table. **Old reports are never deleted automatically** — every run adds a new timestamped file so the directory doubles as a compliance evidence trail.

## `secrets/soc2.config.private.yaml` fields

This file is deep-merged onto `config/soc2.config.yaml` at load time (`common/config.py`) - dicts merge key-by-key, but lists (like `manual_review_urls`) replace the public default wholesale rather than appending to it. It's entirely optional per-field: only set the ones your setup actually needs, anything left unset just falls back to the committed config's default.

| Key | Type | Used by | What it's for |
|---|---|---|---|
| `bitbucket.account_email` | string | Bitbucket (`auth_mode: basic_email`) | The real account's email for Basic auth. Shared value with `gsuite.delegated_admin_email` / `confluence.account_email` below - same person, set once conceptually, three times in the file since each provider reads its own key. |
| `bitbucket.workspaces` | list of strings | Bitbucket | Which workspace(s) to scan. Bitbucket's token type here can't auto-discover workspaces (`GET /2.0/workspaces` is deprecated platform-wide - see `references/bitbucket_setup.md`), so this must be pinned explicitly. |
| `bitbucket.manual_review_urls` | list of strings | Bitbucket (report only) | URLs shown under "Manual review required" in the report for things Bitbucket's API can't expose at all (Access Tokens, SSH keys/OAuth clients/applications/access-controls pages) - workspace-specific, so hardcoded per-company rather than in the public config. |
| `gcp.manual_review_urls` | list of strings | GCP (report only) | Same idea as Bitbucket's - project-specific console URLs for things with no public API (OAuth 2.0 Client IDs on the Credentials page, etc). |
| `gcp.firewall_name_highlights` | list of strings | GCP | Substrings/prefixes of firewall rule or network names to highlight (green) in the Firewall Rules table - useful for calling out this company's specific fleet/network naming conventions. |
| `gcp.storage_bucket_collapsible_groups` | list of `{label, prefix}` or `{label, substrings: [...]}` | GCP | Folds large, low-signal fleets of same-pattern storage buckets (e.g. hundreds of per-customer buckets sharing a naming convention) into a collapsible `<details>` section in the Storage Bucket Config chapter, instead of drowning out the genuinely distinct ones. `prefix` is a startswith match; `substrings` is any-of. |
| `gsuite.delegated_admin_email` | string | Google Workspace | The Workspace user to impersonate via domain-wide delegation for Admin SDK calls - must already be authorized for this service account's Client ID in the Workspace Admin Console (see `references/gsuite_setup.md`). Shared value with `bitbucket.account_email` / `confluence.account_email`. |
| `confluence.cloud_id` | string | Confluence | The site's Atlassian Cloud ID, required to route requests through the centralized API gateway (`api.atlassian.com/ex/confluence/{cloud_id}/...`) instead of the site's own domain. How to find it (via an unauthenticated redirect chain) is documented in `references/confluence_setup.md`. |
| `confluence.main_space` | string, optional | Confluence | Narrows the scan to one space key (e.g. `"PRD"`) instead of enumerating every space this account can see (1000+ in a typical instance). When set, that one space gets full per-user permission detail (including group grants resolved to real members) and every other space collapses into a single "N other authorized spaces" note. Leave unset to fall back to listing every space with just its admins. |
| `confluence.account_email` | string | Confluence (Basic auth) | Same shared identity as `bitbucket.account_email` above. |

## Project structure

```
config/soc2.config.yaml          # non-secret settings (which projects/workspaces/region, check toggles) - safe to make public
secrets/                         # credentials — gitignored, never committed
secrets/soc2.config.private.yaml # company-identifying values deep-merged onto config/soc2.config.yaml - gitignored
.state/snapshots/<provider>/     # JSON snapshots per run — gitignored
reports/                         # generated Markdown reports — gitignored
.claude/skills/soc2/
  SKILL.md                       # full description of every check + report layout
  references/                    # per-provider setup guides (IAM roles, API scopes, known gaps)
  scripts/
    soc2_scan.py                 # CLI entrypoint
    check_permissions.py         # GCP permission pre-flight probe
    common/                      # config loading, snapshot diffing, redaction, report rendering, schema
    providers/                   # one scanner module per provider (gcp/aws/bitbucket/trello/gsuite/confluence)
```

## Security notes

- **Never commit `secrets/`.** It's gitignored (the whole directory, including `soc2.config.private.yaml`); double-check before any `git add -A`.
- **Nothing under `secrets/` is ever echoed.** All scripts scrub registered secret values from console output, snapshots, and reports (`common/redact.py`) before writing anything. Shared identity values (like the delegated-admin email) are deliberately *not* registered as secrets, since they legitimately appear as real report content (e.g. group ownership, permission grants) — only genuine credential material (tokens, private keys) gets scrubbed.
- **Scanner credentials are read-only everywhere.** If a check needs a write permission the scanner doesn't have (e.g. fixing a finding), that's a deliberate boundary — remediation is a separate, explicit step the operator takes with their own credentials, not something this tool does on its own. For Google Workspace this was confirmed empirically, not just assumed: a delete call against a fake email was rejected with a 403 at the authorization layer, before Google even looked up the target.

## Sample report

A fully fictional excerpt of the Markdown output, covering most chapters across all six providers to show the formatting conventions described above (severity colors, grouped/nested rows, collapsible fleets, gray-highlighted staleness). Company name, project IDs, emails, repo/bucket/instance names, and every finding below are made up for illustration — not real scan data.

### Executive Summary

| Severity | Count |
|---|---|
| **<span style="color:darkred; text-decoration:underline">critical</span>** | 6 |
| **<span style="color:red">high</span>** | 19 |
| **<span style="color:orange">medium</span>** | 41 |
| low | 5 |
| info | 212 |

### GCP


#### Service Accounts (enabled)

---

**(info) build-agent@example-project-123456.iam.gserviceaccount.com** — Has Key(s): yes (1)

Description: CI build agent for the deploy pipeline

Last Seen: usage: 2026-07-10 | per-API: never seen | key-auth: 2026-07-10 | per-key: 2026-07-10 (key ...a1b2c3d4)

| Key ID | Key Type | Age (days) | Created |
|---|---|---|---|
| 9f8e7d6c5b4a... | USER_MANAGED | 812 | 2024-04-28 |

Permissions:

- roles/editor (**<span style="color:red">high</span>**)

---

---

**(info) data-export@example-project-123456.iam.gserviceaccount.com** — Has Key(s): no

Last Seen: usage: never seen | per-API: never seen | key-auth: never seen | per-key: never seen

Permissions:

- roles/bigquery.dataViewer (info)
- roles/storage.objectViewer (info)

---

#### IAM Bindings - Users

| Severity | User | Roles |
|---|---|---|
| **<span style="color:red">high</span>** | user:admin@example.com | roles/owner (**<span style="color:red">high</span>**) |
| **<span style="color:red">high</span>** | user:carol@example.com | roles/editor (**<span style="color:red">high</span>**)<br>roles/secretmanager.admin (info) |
| info | user:dave@example.com | roles/viewer (info) |

#### Firewall Rules (enabled)

| Severity | Name | Network | Direction | Source Ranges | Ports |
|---|---|---|---|---|---|
| **<span style="color:darkred; text-decoration:underline">critical</span>** | allow-all-ssh | default | INGRESS | 0.0.0.0/0 | tcp:22(ssh) |
| **<span style="color:red">high</span>** | allow-web | prod-vpc | INGRESS | 0.0.0.0/0 | tcp:80(http), tcp:443(https) |
| info | allow-internal | prod-vpc | INGRESS | 10.0.0.0/8 | tcp:443(https) |

#### Security Command Center Findings (438 findings across 6 resource groups, 3 sections)

##### Compute - Instances (2 groups)

**"compute.googleapis.com/projects/example-project-123456/zones/*/instances/" :**
- worker-fleet-mig-*
- worker-fleet-eu-mig-*

| Category | Count | Severity |
|---|---|---|
| OS_VULNERABILITY | 22 | **<span style="color:darkred; text-decoration:underline">critical</span>** |
| PUBLIC_IP_ADDRESS | 4 | **<span style="color:red">high</span>** |
| COMPUTE_SECURE_BOOT_DISABLED | 2 | **<span style="color:orange">medium</span>** |

---

**"compute.googleapis.com/projects/example-project-123456/zones/*/instances/" :**
- build-agent-0

| Category | Count | Severity |
|---|---|---|
| SOFTWARE_VULNERABILITY | 6 | **<span style="color:darkred; text-decoration:underline">critical</span>** |
| COMPUTE_SERIAL_PORTS_ENABLED | 1 | **<span style="color:orange">medium</span>** |

#### Storage Bucket Config

| Severity | Name | Location | Uniform Access | Public Access Prevention | Versioning |
|---|---|---|---|---|---|
| **<span style="color:orange">medium</span>** | example-terraform-state | US | True | inherited | False |
| info | example-app-backups | US-CENTRAL1 | True | enforced | True |

<details><summary><span style="color:green">Buckets matching *.reports.example.com (241)</span></summary>

| Severity | Name | Location | Uniform Access | Public Access Prevention | Versioning |
|---|---|---|---|---|---|
| **<span style="color:orange">medium</span>** | 1000001.reports.example.com | US | False | inherited | False |
| **<span style="color:orange">medium</span>** | 1000002.reports.example.com | US | False | inherited | False |
| ... | ... | ... | ... | ... | ... |

</details>

#### Org Policy Constraints

| Severity | Constraint | Enforced |
|---|---|---|
| info | constraints/compute.requireOsLogin | **<span style="color:red">no</span>** |
| info | constraints/compute.requireShieldedVm | **<span style="color:red">no</span>** |
| info | constraints/iam.disableServiceAccountKeyCreation | yes |
| info | constraints/storage.publicAccessPrevention | **<span style="color:red">no</span>** |
| info | constraints/sql.restrictPublicIp | yes |

### AWS

#### Root Account

| Severity | MFA Enabled | Access Keys Present | Signing Certs Present |
|---|---|---|---|
| info | yes | no | no |

#### IAM Users

| Severity | User Name | Console Access | MFA Enabled | Password Last Used |
|---|---|---|---|---|
| **<span style="color:red">high</span>** | alice | yes | no | <span style="color:red">2024-02-11</span> |
| **<span style="color:red">high</span>** | bob | yes | no | 2026-06-30 |
| info | ci-deploy | no | n/a | n/a |

#### Security Groups

| Severity | Group ID | Group Name | VPC | Ingress Rules |
|---|---|---|---|---|
| **<span style="color:darkred; text-decoration:underline">critical</span>** | sg-0a1b2c3d | ssh-open-legacy | vpc-01234567 | tcp:22 from 0.0.0.0/0 |
| **<span style="color:red">high</span>** | sg-0f9e8d7c | web-tier | vpc-01234567 | tcp:80 from 0.0.0.0/0<br>tcp:443 from 0.0.0.0/0 |

#### S3 Buckets

| Severity | Bucket Name | Public (ACL) | Public (Policy) | Block Public Access |
|---|---|---|---|---|
| **<span style="color:darkred; text-decoration:underline">critical</span>** | example-public-assets | no | **<span style="color:red">yes</span>** | **<span style="color:red">no</span>** |
| info | example-app-logs | no | no | yes |

### Bitbucket

#### Repos

| Severity | Workspace | Repo | Private | Last Updated |
|---|---|---|---|---|
| info | example-team | api-service | yes | 2026-07-09 |
| info | example-team | legacy-batch-job | yes | <span style="color:red">2025-08-14</span> |

#### Repo Permissions

| Severity | Principal | Repo Access |
|---|---|---|
| **<span style="color:red">high</span>** | Alice Johnson | example-team/api-service (**<span style="color:red">admin</span>**)<br>example-team/legacy-batch-job (**<span style="color:red">admin</span>**) |
| info | Bob Martinez | example-team/api-service (write) |

#### Account SSH Keys

| Severity | Account | Workspace | Keys |
|---|---|---|---|
| **<span style="color:orange">medium</span>** | example-team (workspace) | example-team | alice@example.com (Last Used: never), bob@example.com (Last Used: 2025-11-02) |

### Trello

#### Board Members

| Severity | Member | Last Active | Board Access |
|---|---|---|---|
| **<span style="color:orange">medium</span>** | Carol Diaz (carold) | <span style="color:red">2025-09-02</span> | <span style="background-color:#d9d9d9;">Old Marketing Ideas (closed) (normal)</span><br>Engineering Roadmap (**<span style="color:red">admin</span>**)<br>Onboarding (normal) |
| info | Dave Kim (davek) | 2026-07-08 | Engineering Roadmap (normal)<br>Support Queue (normal) |

### Google Workspace

#### Admin Summary

| Severity | Super Admin Count | Super Admins | Delegated Admin Count |
|---|---|---|---|
| info | 2 | admin@example.com, alice@example.com | 0 |

#### Users (enabled)

| Severity | Email | Name | Admin | 2FA Enrolled | 2FA Enforced | Last Login | Org Unit |
|---|---|---|---|---|---|---|---|
| info | admin@example.com | Admin User | **yes** | yes | yes | 2026-07-01 | / |
| **<span style="color:red">high</span>** | bob@example.com | Bob Martinez | no | **<span style="color:red">no</span>** | **<span style="color:red">no</span>** | 2026-06-20 | / |
| **<span style="color:orange">medium</span>** | finance@example.com | Accounting Team | no | yes | yes | <span style="color:red">2020-04-22</span> | / |

#### Groups

| Severity | Email | Name | Members | Owners | Managers |
|---|---|---|---|---|---|
| info | engineering@example.com | Engineering | 12 | admin@example.com | none |
| info | finance@example.com | Finance | 3 | none | none |

#### Mobile Devices

| Severity | Owner | Devices |
|---|---|---|
| **<span style="color:red">high</span>** | alice@example.com | Pixel 8 (OS: Android 15, Status: APPROVED, Compromised: Undetected, Encrypted: Encrypted, Password Set: On, Last Sync: 2026-07-01)<br><span style="background-color:#d9d9d9;">iPhone 11 (OS: iOS 15.2, Status: APPROVED, Compromised: No compromise detected, Encrypted: , Password Set: On, Last Sync: 2023-04-12)</span> |

#### OAuth App Grants

| Severity | User | Grants |
|---|---|---|
| info | bob@example.com | 2026-07-05T09:12:03 ( to 2026-06-01T08:47:11 ) - **Google Chrome**: OAuthLogin<br>2026-06-20T14:03:55 - **Slack**: <span style="color:orange">drive.readonly</span>, userinfo.email, openid |

### Confluence

#### Spaces

| Severity | Key | Name | Type | Status | Anonymous Access | Admins |
|---|---|---|---|---|---|---|
| info | ENG | Engineering Wiki | global | current | no | Alice Johnson, Carol Diaz, group:administrators |

#### Space Permissions - Other (enabled)

| Severity | Space | Subject | Type | Operations | Via |
|---|---|---|---|---|---|
| **<span style="color:red">high</span>** | ENG | carol@example.com | user | administer:space, create:page, read:space | direct |
| info | ENG | dave@example.com | user | create:comment, read:space | direct |

#### Other Authorized Spaces

| Severity | Note |
|---|---|
| info | Detected another 47 authorized space(s) under this account (not scanned in detail - see main_space in config) |

#### Changes since last scan (example, Bitbucket)

| Change | Severity | Type | ID | Details |
|---|---|---|---|---|
| added | **<span style="color:red">high</span>** | bitbucket.repo_permission | example-team/api-service:alice | |
| removed | info | bitbucket.deploy_key | example-team/legacy-batch-job:old-ci-key | |
| modified | **<span style="color:orange">medium</span>** | aws.s3.bucket | example-public-assets | block_public_access_enabled: True → False |

_The real report also includes a full table of contents, every other chapter (IAM Recommendations, Cloud Asset public bindings, Secret Manager, Cloud SQL, GKE, Cloud DNS, IAM Access Advisor, VPC Flow Logs, CloudTrail, Webhooks, Branch Restrictions, Org Units, Suspicious Login Events, and more), and a "Changes since last scan" table for every provider that has a prior snapshot to diff against — this excerpt only shows enough of each to illustrate the formatting conventions above._

## Reference docs

- [`references/gcp_setup.md`](.claude/skills/soc2/references/gcp_setup.md) — required APIs/IAM roles per check, known gaps
- [`references/aws_setup.md`](.claude/skills/soc2/references/aws_setup.md) — IAM policy setup, region scoping, best-effort checks
- [`references/bitbucket_setup.md`](.claude/skills/soc2/references/bitbucket_setup.md) — token-type detection, endpoints used, confirmed platform gaps
- [`references/trello_setup.md`](.claude/skills/soc2/references/trello_setup.md) — generating a read-scoped Trello key/token
- [`references/gsuite_setup.md`](.claude/skills/soc2/references/gsuite_setup.md) — domain-wide delegation setup (reusing the GCP service account), and how the read-only scope enforcement was empirically verified
- [`references/confluence_setup.md`](.claude/skills/soc2/references/confluence_setup.md) — Atlassian API-gateway routing (vs. the site's own domain), cloud ID discovery, `main_space` narrowing, group-membership resolution
- [`references/snapshot_schema.md`](.claude/skills/soc2/references/snapshot_schema.md) — the shared Resource/Snapshot JSON schema and diff algorithm
