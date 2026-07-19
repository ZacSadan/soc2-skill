---
name: soc2
description: This skill should be used when the user asks to "run a SOC2 scan," "security compliance check," "audit GCP IAM permissions," "check for public firewall rules," "review Bitbucket repository access," "scan Trello board access," "audit AWS IAM/security groups," "check Google Workspace 2FA/admin status," "review Confluence space permissions," or wants a security/access inventory across GCP, Bitbucket, Trello, AWS, Google Workspace, and Confluence with a diff against the previous scan.
---

# SOC2 Security Scanner

Inventories the security posture of GCP, Bitbucket, Trello, AWS, Google Workspace, and Confluence. Every run prints a console summary, saves a timestamped JSON snapshot per provider, diffs against the previous snapshot for that provider, and writes a Markdown report suitable for pasting into tickets or compliance evidence folders.

Run selectively (`--scope gcp`, `--scope bitbucket`, `--scope trello`, `--scope aws`, `--scope gsuite`, `--scope confluence`) or all at once (`--scope all`, the default).

## Prerequisites

- Credentials live under `secrets/` at the repo root (gitignored, never committed):
  - `secrets/gcp-service-account.json` — GCP service-account key
  - `secrets/id-atlassian-bitbucket-token.txt` — Bitbucket API token (dedicated Atlassian account, Basic auth)
  - `secrets/id-atlassian-confluence-token.txt` — Confluence API token (same Atlassian account family as Bitbucket); see `references/confluence_setup.md`
  - `secrets/trello-credentials.json` — `{"api_key": "...", "token": "..."}`, added by the user; see `references/trello_setup.md`
  - `secrets/aws-access-keys.csv` — the CSV downloaded from IAM > Users > Security credentials > Create access key; see `references/aws_setup.md`
  - `secrets/soc2.config.private.yaml` — the shared delegated-admin identity's email, set inline (`gsuite.delegated_admin_email`, `bitbucket.account_email`, `confluence.account_email`), plus other company-identifying values (workspace names, hardcoded manual-review URLs, name-highlight patterns) deep-merged onto `config/soc2.config.yaml` at load time — used by three providers: Google Workspace (domain-wide delegation impersonation, reuses `secrets/gcp-service-account.json`, no separate key), Bitbucket's `basic_email` auth mode, and Confluence's Basic auth — one identity, one value, not three copies of the same email; see `references/gsuite_setup.md`
- Non-secret settings live in `config/soc2.config.yaml` at the repo root (which GCP projects/Bitbucket workspaces/Trello orgs/AWS region to scan, thresholds, output paths).
- Python dependencies: `pip install -r .claude/skills/soc2/scripts/requirements.txt`

Before the first GCP scan, run the permission pre-flight probe so missing permissions or disabled APIs show up as a clear table instead of a crash mid-scan:

```
python .claude/skills/soc2/scripts/check_permissions.py
```

## Running scans

```
python .claude/skills/soc2/scripts/soc2_scan.py --scope all         # everything
python .claude/skills/soc2/scripts/soc2_scan.py --scope gcp         # GCP only
python .claude/skills/soc2/scripts/soc2_scan.py --scope bitbucket   # Bitbucket only
python .claude/skills/soc2/scripts/soc2_scan.py --scope trello      # Trello only
python .claude/skills/soc2/scripts/soc2_scan.py --scope aws         # AWS only
python .claude/skills/soc2/scripts/soc2_scan.py --scope gsuite      # Google Workspace only
python .claude/skills/soc2/scripts/soc2_scan.py --scope confluence  # Confluence only
```

Useful flags:
- `--no-diff` — skip comparing against the previous snapshot.
- `--no-report` — skip writing the Markdown report (still writes JSON snapshots).
- `--json-only` — write snapshots only, no console output or report.
- `--config <path>` — use a config file other than `config/soc2.config.yaml`.

Each run exits with a nonzero status if any `critical`/`high` severity finding is present in the current results — useful for CI gating.

## What gets scanned

| Provider | Checks |
|---|---|
| GCP | IAM service accounts + user-managed keys (flags old/unrotated keys), project IAM policy bindings (with included permissions expanded for custom roles only - predefined roles, including granular ones, are never expanded), Compute Engine firewall rules (flags public + sensitive-port exposure, labels well-known ports), SSH key metadata (project and instance level, grouped by username), API Keys (flags unrestricted keys as high severity), Security Command Center findings, IAM Recommender, usage metrics, Cloud Asset public IAM bindings (any public resource-level binding project-wide, not just the project policy), Cloud KMS key rotation, Cloud SQL instance exposure (public IP + open authorized networks / SSL), Secret Manager rotation policies, Cloud Logging sinks, Artifact Registry public repos, Pub/Sub public topics (best-effort — see known gap in `references/gcp_setup.md`), GKE cluster security config (legacy ABAC, basic/cert auth, private nodes, master-authorized-networks, Workload Identity, Binary Authorization), Cloud DNS zone DNSSEC status, Storage bucket hardening config (uniform bucket-level access, public access prevention, versioning - complements Cloud Asset's IAM-only view), and Org Policy constraint state for 4 curated security-relevant constraints (all best-effort — see `references/gcp_setup.md`). Report is organized into dedicated chapters (see Output below), not a flat list. |
| Bitbucket | Repos (sorted by name), per-repo access levels (grouped by principal), repo-level deploy keys, project-level access keys, account SSH keys (all credential-listing checks are best-effort - see caveat below), webhooks, branch restrictions (which also cover merge checks - required approvals / required passing builds - via the restriction's `kind` field, auto-detects Bearer vs Basic+email auth — see `references/bitbucket_setup.md`). Also organized into dedicated chapters, same as GCP. 2FA enforcement and IP allowlisting were investigated and confirmed to have no public API at all (UI-only, same category as Access Tokens) - see `references/bitbucket_setup.md`. |
| Trello | Organizations, organization-level membership (admin/normal, flags deactivated/unconfirmed accounts), boards (visibility, last activity), board members and per-board permission level grouped by member (no-ops with a clear message until credentials are configured — see `references/trello_setup.md`). Also organized into dedicated chapters, same as GCP/Bitbucket/AWS. |
| AWS | Root account MFA/access-key status, IAM users (console access + MFA status, grouped by principal for bindings) with password-staleness flagged past 6 months, access keys (flags old/unrotated keys), IAM Access Advisor (service-last-accessed, flags granted-but-never-used access), IAM roles (flags public trust policies), IAM policy bindings across users/roles/groups (flags admin-equivalent managed policies), IAM account password policy, EC2 security groups (flags public + sensitive-port exposure), EC2 key pairs, EBS default encryption, VPC Flow Logs coverage, S3 bucket public exposure (ACL/policy/Block Public Access), API Gateway keys, CloudTrail logging/multi-region/log-file-validation status, AWS Config recorder status, KMS customer-managed key rotation, RDS instance public exposure/encryption, cross-region resource inventory via Resource Explorer, and Security Hub/GuardDuty/Access Analyzer findings (all best-effort — see `references/aws_setup.md`). All 7 of the newest checks (password policy, CloudTrail, Config, KMS, RDS, EBS default encryption, VPC Flow Logs) run under the same `SecurityAudit` policy already required for the rest of the scanner - no additional IAM grant needed. IAM, S3, CloudTrail, Config, KMS, and the root account summary are global; EC2/API Gateway/Security Hub/GuardDuty/Access Analyzer/Resource Explorer/RDS's default-region view only cover the single configured region (`aws.region`, default `us-east-1`) - Resource Explorer inventory itself is the one exception that can surface other regions' resources, when enabled. Also organized into dedicated chapters, same as GCP/Bitbucket. |
| Google Workspace | User directory via domain-wide delegation (reuses the GCP service account, no new credential): suspended/active/archived status, admin/delegated-admin flags, 2FA enrollment vs. enforcement (flags admins without enforced 2FA as critical, any active user with no 2FA as high), dormant-but-active accounts (no login in 6+ months), and a super-admin-count summary (2-4 recommended, flags 0/1/5+); groups and group owner/manager membership; org unit hierarchy; mobile device posture (compromised/unencrypted/no-screen-lock flagged); and two Reports-API-derived chapters covering the last `audit_lookback_days` (default 30): Suspicious Login Events (curated concerning event types, not routine success/failure) and OAuth App Grants (which apps were authorized, by whom, what scopes — read via the Reports API specifically to avoid the write-capable `admin.directory.user.security` scope). No-ops with a clear message until `gsuite.delegated_admin_email` is configured — see `references/gsuite_setup.md`, including how the read-only scope enforcement was empirically verified. Also organized into dedicated chapters, same as the other providers. |
| Confluence | Every space (global/personal/knowledge-base), flagging anonymous/public access on any permission (critical — the Confluence analog of a public bucket/repo) and listing who holds `administer` on each space (users, groups, and Marketplace app integrations alike). Requests route through Atlassian's centralized API gateway rather than the site's own domain — this site's domain is fronted by an SSO-enforcement proxy that rejects direct API-token auth; see `references/confluence_setup.md` for how that was diagnosed. Also organized into dedicated chapters, same as the other providers. |

Every Bitbucket check that gets a non-404 HTTP error (403 included) records it as a skipped check under that provider's "Skipped/errored checks" in the report rather than silently showing zero results - a 403 there almost always means the configured token is missing a scope, and Bitbucket's error body names exactly which one (e.g. repo deploy keys need `repository`/`repository:admin`; project access keys need `project`/`project:admin`). Bitbucket also rejects the account-SSH-keys endpoint outright for Bearer/access-token auth ("not accessible by this authentication mechanism", not a scope you can grant) - it may still work under `auth_mode: basic_email`. Bitbucket's public REST API has no endpoint at all to list Access Tokens (repo-, project-, or workspace-scoped) - every path returns "no API hosted at this URL" regardless of scope, so Access Tokens are intentionally not scanned; check the Bitbucket UI directly for those. There is also no workspace-level Access Keys feature in Bitbucket - only repo, project, and account levels have SSH keys.

## Output

- **Console**: fixed order GCP → Bitbucket → Trello → AWS. GCP, Bitbucket, and AWS resources are split into dedicated chapters (each shown enabled-group-first-then-disabled-group where the resource type has a real enabled/disabled state) instead of one flat list — GCP: Service Accounts (each account's description, user-managed keys, usage/key-auth timestamps, and directly-bound IAM roles nested underneath it, not separate chapters), IAM Bindings - Users (grouped one row per user with every role - and, for custom roles, every included permission - they hold), IAM Bindings - Groups (group: bindings only; serviceAccount: bindings are already nested under Service Accounts), Firewall Rules (well-known ports labeled, e.g. `80(http)`; fully-open `all:all` rules and non-`/32` source ranges bolded; certain fleet/network name substrings colored), SSH Keys (grouped by username), API Keys, Security Command Center Findings, IAM Recommendations, Cloud Asset - Public IAM Bindings, Cloud KMS Keys, Cloud SQL Instances, Secret Manager Secrets, Cloud Logging Sinks, Artifact Registry Repositories, Pub/Sub Topics, GKE Clusters, Cloud DNS Zones, Storage Bucket Config, Org Policy Constraints; Bitbucket: Repos, Repo Permissions (grouped by principal, alphabetized, admin/write permission levels highlighted), Deploy Keys, Project Access Keys, Account SSH Keys (grouped by account), Webhooks, Branch Restrictions; AWS: Root Account, IAM Users (stale passwords past 6 months in red), IAM Access Keys, IAM Access Advisor, IAM Roles, IAM Bindings (grouped by principal), Security Groups (each ingress rule on its own line), EC2 Key Pairs, S3 Buckets, API Gateway Keys, Security Hub Findings, GuardDuty Findings, Access Analyzer Findings, Resource Explorer Inventory, CloudTrail, AWS Config Recorder, IAM Password Policy, KMS Keys, RDS Instances, EBS Default Encryption, VPCs; Trello: Organization Members, Boards, Board Members (grouped by member, every board + permission level nested underneath); Google Workspace: Admin Summary, Users (2FA/admin/last-login columns, suspended users in their own gray group); Confluence: Spaces (anonymous access bold-red-flagged, admins listed per space). Bitbucket, Trello, AWS, Google Workspace, and Confluence all show their diff-since-last-scan chapter first (GCP has none). In the Markdown report, `critical`/`high` severity values render bold red (skipped for disabled resources) and disabled Service Accounts / Firewall Rules render on a gray background. Any chapter can define `collapsible_groups` (a list of `(label, predicate)` pairs) to fold a large, low-signal fleet of same-pattern resources (e.g. hundreds of per-customer buckets sharing a naming convention) into a `<details>` section in the Markdown report, keeping the visible table down to the genuinely distinct resources - console output is unaffected since it already truncates to `console_top_findings`.
- **JSON snapshots**: `.state/snapshots/<provider>/<provider>-<timestamp>.json` — one file per provider per run, always diffed against that provider's own most recent prior snapshot regardless of what `--scope` produced either of them. See `references/snapshot_schema.md` for the data model.
- **Markdown report**: `reports/soc2-report-<scope>-<timestamp>.md` — executive summary, per-provider findings tables, and a diff-since-last-time table. Both the GCP and Bitbucket sections end with a hardcoded "Manual review required" list of URLs for things their APIs can't expose at all (GCP: OAuth 2.0 Client IDs, a known long-standing platform gap - API Keys on the same Credentials page *are* scanned automatically, via the API Keys API) or gate behind admin scope this scanner doesn't hold (Bitbucket: Atlassian account API tokens, and this workspace/project's access keys, access tokens, SSH keys, add-ons, OAuth clients, applications, and access controls pages).

## Critical rule: never echo secrets

Never print, paste, or write the contents of any file under `secrets/`, or any raw API token/private key, into chat output, snapshots, or reports. The scripts already scrub registered secret values from everything they write (`common/redact.py`) — do not bypass that by manually `cat`-ing credential files.

## Reference Files

- `references/gcp_setup.md` — required APIs/IAM roles, and why SCC/Recommender are best-effort
- `references/bitbucket_setup.md` — token-type detection tiers and endpoints used
- `references/trello_setup.md` — how to generate a dedicated read-scoped Trello key/token
- `references/aws_setup.md` — IAM user/policy setup, region scoping, and why Security Hub/Access Analyzer are best-effort
- `references/gsuite_setup.md` — domain-wide delegation setup (reusing the GCP service account), and how the read-only scope enforcement was empirically verified
- `references/confluence_setup.md` — Atlassian API-gateway routing (vs. the site's own domain), cloud ID discovery, and the admin-operation-name bug found during this build
- `references/snapshot_schema.md` — the shared Resource/Snapshot JSON schema and diff algorithm
