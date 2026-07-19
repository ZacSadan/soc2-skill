# GCP Setup

## Service account

The scanner authenticates with the key at `secrets/gcp-service-account.json`, scoped to `https://www.googleapis.com/auth/cloud-platform`. The narrower `cloud-platform.read-only` variant was tried first but rejected several IAM/Compute read methods outright (`ACCESS_TOKEN_SCOPE_INSUFFICIENT`) even with a correctly-granted read-only IAM role — OAuth scope is only a ceiling, so the actual security boundary here is the IAM roles below, not the scope.

## Required APIs (enable on the target project)

- Identity and Access Management (IAM) API — `iam.googleapis.com`
- Cloud Resource Manager API — `cloudresourcemanager.googleapis.com`
- Compute Engine API — `compute.googleapis.com`
- API Keys API — `apikeys.googleapis.com` (lists API Keys under APIs & Services > Credentials; covered by the same `roles/iam.securityReviewer` grant below - no separate role needed)
- (best-effort) Security Command Center API — `securitycenter.googleapis.com`
- (best-effort) Recommender API — `recommender.googleapis.com`
- (best-effort) Cloud Monitoring API — `monitoring.googleapis.com`

## Required IAM roles

The following predefined roles cover every core check:

- `roles/iam.securityReviewer` — service accounts, keys, IAM policy read
- `roles/compute.viewer` — firewall rules, instance/project metadata (SSH keys)

Grant with:

```
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:soc2-skill@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/iam.securityReviewer"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:soc2-skill@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/compute.viewer"
```

### Extended read-only roles (9 additional checks)

Beyond the core two roles above, each of these adds one narrowly-scoped check. All are read-only viewer/reader roles - none grant write access:

| Role | Enables |
|---|---|
| `roles/cloudasset.viewer` | Cloud Asset - Public IAM Bindings (`scan_cloud_asset_public_bindings`) - finds `allUsers`/`allAuthenticatedUsers` bindings on *any* resource in the project (buckets, Cloud Run services, BigQuery datasets, etc.), not just the project-level policy `scan_iam_bindings` already covers |
| `roles/cloudkms.viewer` | Cloud KMS Keys (`scan_kms_key_rotation`) - flags encryption keys with no automatic rotation configured |
| `roles/cloudsql.viewer` | Cloud SQL Instances (`scan_cloud_sql_instances`) - flags public-IP instances with an open (`0.0.0.0/0`) authorized network or SSL not required |
| `roles/secretmanager.viewer` | Secret Manager Secrets (`scan_secret_manager_secrets`) - flags secrets with no rotation policy configured |
| `roles/logging.viewer` | Cloud Logging Sinks (`scan_logging_sinks`) - lists log export sinks, flags whether any point outside this project (an external/immutable audit trail) |
| `roles/artifactregistry.reader` | Artifact Registry Repositories (`scan_artifact_registry_repos`) - flags any repository with a public IAM binding |
| `roles/pubsub.viewer` | Pub/Sub Topics (`scan_pubsub_public_topics`) - flags any topic with a public IAM binding; see the known gap below - this role alone cannot actually confirm the "none" case |
| `roles/container.viewer` | GKE Clusters (`scan_gke_clusters`) - flags legacy ABAC, basic/client-cert auth, missing private-nodes, missing master-authorized-networks allowlist |
| `roles/dns.reader` | Cloud DNS Zones (`scan_dns_zones`) - flags public zones without DNSSEC enabled |

```
for role in cloudasset.viewer cloudkms.viewer cloudsql.viewer secretmanager.viewer logging.viewer artifactregistry.reader pubsub.viewer container.viewer dns.reader; do
  gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:soc2-skill@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/$role"
done
```

Each also needs its API enabled on the project (`cloudasset.googleapis.com`, `cloudkms.googleapis.com`, `sqladmin.googleapis.com`, `secretmanager.googleapis.com`, `logging.googleapis.com`, `artifactregistry.googleapis.com`, `pubsub.googleapis.com`, `container.googleapis.com`, `dns.googleapis.com`) - a disabled API degrades that one check to a skipped entry rather than failing the scan, same posture as SCC/Recommender below.

### 3 further extended checks

| Check | Role/permission needed | Enables |
|---|---|---|
| Storage Bucket Config (`scan_storage_bucket_config`) | `storage.buckets.list`/`storage.buckets.get` - granted by `roles/storage.admin`, or the narrower `roles/storage.legacyBucketReader` bound at the project level | Flags buckets without uniform bucket-level access, without public access prevention enforced, or without versioning - complements the Cloud Asset public-bindings check above, which covers *who* has access, not the bucket's own hardening config |
| Org Policy Constraints (`scan_org_policies`) | `roles/orgpolicy.policyViewer` + the Organization Policy API (`orgpolicy.googleapis.com`) enabled | Reports the effective state of 14 curated constraints: `iam.allowedPolicyMemberDomains` (domain-restricted sharing), `iam.disableServiceAccountKeyCreation`, `iam.disableServiceAccountKeyUpload`, `iam.disableServiceAccountCreation`, `sql.restrictPublicIp`, `sql.restrictAuthorizedNetworks`, `compute.vmExternalIpAccess`, `compute.requireOsLogin`, `compute.requireShieldedVm`, `compute.disableSerialPortAccess`, `compute.skipDefaultNetworkCreation`, `compute.restrictVpcPeering`, `storage.publicAccessPrevention`, `storage.uniformBucketLevelAccess`. Purely informational (`info` severity) - whether these "should" be enforced is an organizational choice, not scored as a finding |
| GKE Clusters (extended) | No new role - uses the existing `roles/container.viewer` grant | Now also reports Workload Identity and Binary Authorization status per cluster; a cluster with private nodes + master-authorized-networks but no Workload Identity is flagged `low` (nodes may still rely on long-lived service account keys instead of federated identity) |

### Known gap: Pub/Sub per-topic IAM policy checks

`scan_pubsub_public_topics` lists topics fine with `roles/pubsub.viewer`, but reading a topic's actual IAM policy needs the `pubsub.topics.getIamPolicy` permission - which, verified against Google's live Pub/Sub access-control docs, is present only in `roles/pubsub.editor` and `roles/pubsub.admin`, **not** `roles/pubsub.viewer`. Neither of those write-capable roles is appropriate to grant a read-only compliance scanner, so this check cannot verify the "no public binding" case at all with the roles above - topics list with "Public Bindings: unknown (getIamPolicy denied)" instead of "none". The scanner attempts the call once, and on the first `PERMISSION_DENIED` stops retrying it for the remaining topics in that run (logged as a single skipped-check entry, not one per topic) since the failure is systemic, not resource-specific.

## Security Command Center findings

SCC findings work with ordinary **project-level** IAM roles — no organization-level role grant is required, despite what older SCC documentation and the deprecated v1 API's `organizations.sources.findings.list` endpoint suggest.

`scan_scc_findings` calls SCC's **v2** REST API directly (`GET https://securitycenter.googleapis.com/v2/projects/{project_id}/sources/-/findings`) rather than going through the discovery client used for the other GCP checks, because:
- v1's project-scoped `projects.sources.findings.list` is retired (`400`: "This API is no longer available. Please use API V2").
- v1's org-scoped `organizations.sources.findings.list` requires an organization-level role (`roles/securitycenter.findingsViewer` on the org, not the project) — a much bigger permission grant than this tool needs.
- v2 isn't in `googleapiclient`'s dynamic discovery service at all (`build("securitycenter", "v2", ...)` raises `UnknownApiNameOrVersion`), so it's called via plain authenticated `requests` calls with the same service-account credentials.

The scanner filters to `state="ACTIVE"` by default. Without that filter, this project alone returned over 80,000 findings (mostly long-resolved historical ones) versus ~4,400 active — the unfiltered log would swamp the report and isn't what the GCP Console shows by default either.

If a `PERMISSION_DENIED` still shows up, the service account is missing `securitycenter.findings.list` at the project level — this is normally already covered by `roles/iam.securityReviewer` or a broader viewer role; if not, grant a project-level `roles/securitycenter.findingsViewer`:

```
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:soc2-skill@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/securitycenter.findingsViewer"
```

## IAM Recommender is best-effort

Wrapped so a missing permission or disabled API degrades to a `status: skipped` entry in `errors[]` rather than crashing the scan. Requires the Recommender API enabled and, for the IAM policy recommender specifically, `roles/recommender.iamViewer` (or broader) on the project. In practice the narrower `cloud-platform.read-only` OAuth scope this scanner used to request returned `ACCESS_TOKEN_SCOPE_INSUFFICIENT` for Recommender even with the correct IAM role granted — that's why the full `cloud-platform` scope is used (see above), not a misconfiguration if it recurs.

Run `python .claude/skills/soc2/scripts/check_permissions.py` after any role change to confirm what's now accessible.

## Service account usage metrics (the 4 "last seen" columns)

The Service Accounts paragraphs in the report show 4 columns matching the GCP Console's per-service-account **Metrics** tab: "Service account usage", "Service account usage per API", "Authentication traffic", "Authentication traffic per key". These are derived from two documented Cloud Monitoring metrics rather than 4 separate metric types:

| Report column | Cloud Monitoring metric | Grouped by |
|---|---|---|
| Service account usage | `iam.googleapis.com/service_account/authn_events_count` | nothing (max across all activity for the account) |
| Service account usage per API | same metric | whatever extra `metric.labels` the series carries (e.g. method/service) — shown as `<date> (label=value)` |
| Authentication traffic | `iam.googleapis.com/service_account/key/authn_events_count` | nothing (max across all of this account's keys) |
| Authentication traffic per key | same metric | `metric.labels.key_id` — shown as the specific most-recently-used key |

Requires `roles/monitoring.viewer` (or broader) on the service account:

```
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:soc2-skill@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/monitoring.viewer"
```

Notes and caveats:
- **Retention is 6 weeks.** Cloud Monitoring does not retain these metrics longer, so an account showing "never seen" may simply not have authenticated in the last 42 days, not never.
- **Granularity is daily**, not to-the-minute — dates are aligned to daily buckets to keep query volume bounded (see `scan_usage_metrics` in `providers/gcp_scanner.py`).
- **Per-API grouping is best-effort.** Google's public documentation confirms `resource.labels.unique_id` (service account) and `metric.labels.key_id` (key), but does not fully enumerate every label the `authn_events_count` series may carry for API/method breakdown. If no extra labels are present in a given project's data, "usage per API" will show the same value as "Service account usage."
- Like SCC and IAM Recommender, this check is best-effort: a missing role or disabled API degrades to `status: skipped` for that check (all 4 columns show "never seen"/"unknown") rather than crashing the scan.

## OAuth 2.0 Client IDs are not scanned

The Credentials page (APIs & Services > Credentials) shows two credential types: API Keys and OAuth 2.0 Client IDs. Only API Keys are scanned (`gcp.apikeys.key`, via `apikeys.googleapis.com`) — an API key with no restrictions at all (no API/application/IP restriction) is flagged `high`. OAuth 2.0 Client IDs have no public Google Cloud API to list them at all; this is a known, long-standing platform gap (see the linked feature request in the report's "Manual review required" section), not something this scanner can work around. Review that page by hand.

## Key age thresholds

`gcp.key_age_warn_days` / `gcp.key_age_critical_days` in `config/soc2.config.yaml` control when a user-managed service-account key is flagged `high`/`critical` for being unrotated. Defaults: 90 / 180 days.
