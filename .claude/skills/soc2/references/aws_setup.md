# AWS Setup

## Credentials

The scanner authenticates with a static access key, loaded from the CSV downloaded at IAM > Users > (user) > Security credentials > Create access key. Store it at `secrets/aws-access-keys.csv` (gitignored, never committed) - the file is read as-is, with its `Access key ID`/`Secret access key` columns.

Create a dedicated IAM user for this (e.g. `soc2-skill`) rather than reusing a personal or root credential. When AWS's "Create access key" flow asks for a use case, choose **Local code** - this scanner runs as a script reading credentials from a local file, not from an EC2/ECS/Lambda compute resource (which would use an instance role instead - see below), a CLI tool, or a third-party SaaS product.

If this scanner ever runs *from inside AWS* (an EC2 instance, ECS task, or Lambda), attach the policy below to that resource's execution role instead of creating static access keys at all - no long-lived credential to leak or rotate.

## Required IAM policy

Attach AWS's own built-in **`SecurityAudit`** managed policy (`arn:aws:iam::aws:policy/SecurityAudit`) - it's purpose-built for exactly this kind of read-only security/compliance tool (the same policy tools like Prowler/ScoutSuite use). Verified directly against the live policy document (v89, as of this writing): `SecurityAudit` alone already includes `securityhub:Describe*/Get*/List*`, `guardduty:Get*/List*`, and `access-analyzer:Get*/List*` - so `AWSSecurityHubReadOnlyAccess`, `AmazonGuardDutyReadOnlyAccess`, and `IAMAccessAnalyzerReadOnlyAccess` are **redundant** if `SecurityAudit` is attached; don't bother adding them. The one genuine gap: `SecurityAudit`'s API Gateway statement grants `apigateway:GET` on `/restapis`, `/apis`, stages, models, etc., but **not** on `/apikeys` - so a separate policy is still needed for `scan_api_gateway_keys`:

- `AmazonAPIGatewayAdministrator` (or a narrower inline policy scoped to just `apigateway:GET` on `arn:aws:apigateway:*::/apikeys*`)

No admin-level scope is needed anywhere in this setup - unlike the Bitbucket integration. The root-account, IAM Access Advisor, and S3 public-exposure checks are all covered by `SecurityAudit` itself too (confirmed: `iam:GetAccountSummary`, `iam:GenerateServiceLastAccessedDetails`, `iam:Get*`/`List*`, `s3:GetBucket*`, `s3:GetAccountPublicAccessBlock`, `s3:ListAllMyBuckets` are all explicitly in the policy document).

```
aws iam attach-user-policy --user-name soc2-skill --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-user-policy --user-name soc2-skill --policy-arn arn:aws:iam::aws:policy/AmazonAPIGatewayAdministrator
```

### Don't use `ViewOnlyAccess` instead of `SecurityAudit`

`ViewOnlyAccess` (`arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`) is a *different*, broader-but-shallower policy - it covers resource inventory across more services, but (verified against its live policy document) has **no** `securityhub:*`, `guardduty:*`, or `access-analyzer:*` actions at all, and is missing `s3:GetBucketAcl`/`GetBucketPolicyStatus`/`GetAccountPublicAccessBlock` and `iam:GenerateServiceLastAccessedDetails`/`GetAccessKeyLastUsed`. Using it *instead of* `SecurityAudit` would break Security Hub, GuardDuty, Access Analyzer, S3 bucket exposure, IAM Access Advisor, and the access-key-last-used check entirely - do not swap it in.

Attaching it *in addition to* `SecurityAudit` unlocks exactly one thing this scanner uses: partial Resource Explorer visibility (`resource-explorer-2:GetDefaultView`/`ListViews`/`GetIndex`/`ListIndexes`, none of which are in `SecurityAudit`). "Partial" matters here - confirmed live against a real account with Resource Explorer already indexed: `ViewOnlyAccess` lets `scan_resource_explorer_inventory` discover *that* a default view exists, but the actual `resource-explorer-2:Search` action needed to read its contents is **not** in `ViewOnlyAccess` either, and the search call fails with `AccessDeniedException`. To make Resource Explorer inventory actually work, attach the dedicated policy instead/as well:

- `AWSResourceExplorerReadOnlyAccess` — includes `resource-explorer-2:Get*/List*/Search/BatchGetView` (confirmed against its live policy document)

```
aws iam attach-user-policy --user-name soc2-skill --policy-arn arn:aws:iam::aws:policy/AWSResourceExplorerReadOnlyAccess
```

## Extended checks (7 additional, all covered by `SecurityAudit` alone)

No additional policy is needed for any of these - verified live against a real account:

| Check | What it flags |
|---|---|
| CloudTrail (`scan_cloudtrail_config`) | No trail at all (critical - no audit log exists), a trail not actively logging (critical), single-region trail or log-file-validation disabled (medium) |
| AWS Config Recorder (`scan_config_recorder`) | No recorder configured (medium), recorder configured but not recording (high) |
| IAM Password Policy (`scan_iam_password_policy`) | No account password policy at all (high - AWS's permissive defaults apply), or one below 14 chars / missing a complexity requirement (medium) |
| KMS Key Rotation (`scan_kms_key_rotation`) | Customer-managed symmetric keys with automatic rotation disabled (high); AWS-managed keys are skipped entirely - the account doesn't control their rotation |
| RDS Instances (`scan_rds_instances`) | Publicly-accessible instances (critical), unencrypted storage (medium) |
| EBS Default Encryption (`scan_ebs_default_encryption`) | Account/region-level "encrypt new volumes by default" setting off (medium) - a single global-ish (actually per-region) setting, not per-volume |
| VPC Flow Logs (`scan_vpc_flow_logs`) | Any VPC with no active Flow Log (medium) - no traffic record to investigate after an incident |

## Region scoping

IAM, S3 (`list_buckets`), and the root account summary are global/account-wide and always scanned regardless of `aws.region`. EC2 (security groups, key pairs), API Gateway, Security Hub, GuardDuty, and Access Analyzer are region-scoped - this scanner only covers the single region set in `config/soc2.config.yaml` (`aws.region`, default `us-east-1`), not every region in the account. If resources of interest live in other regions, run the scan once per region (change `aws.region` and re-run) or extend `aws_scanner.scan()` to loop over a list of regions.

## Best-effort checks

- **Security Hub** degrades to a skipped check (not a scan failure) if the account isn't subscribed to Security Hub in that region - same posture as GCP's SCC check.
- **GuardDuty** returns an empty result (not an error) if no detector is enabled in the account/region - same posture as GCP's IAM Recommender check.
- **Access Analyzer** returns an empty result (not an error) if no analyzer is configured in the account/region - same posture as GCP's IAM Recommender check.
- **Resource Explorer** (`scan_resource_explorer_inventory`) skips gracefully if no default view is configured in the account, or if the attached policy can't `Search` it (see the `ViewOnlyAccess`/`AWSResourceExplorerReadOnlyAccess` distinction above) - either way it's a skipped check, not a scan failure. When it does work, it's the only check in this scanner that sees resources outside the single configured `aws.region`, reported as a per-(region, resource type) count.
- **IAM Access Advisor** (`scan_iam_access_advisor`) is asynchronous per AWS user (generate a job, then poll for completion) and only covers IAM Users, not roles, to bound total scan time. A user whose job doesn't complete within a handful of short polls is skipped for that run rather than blocking the whole scan - AWS docs say jobs normally complete within seconds, so a stall is treated as a one-off, not worth failing the run over.

## Known gaps (not scannable via API)

- **Per-instance SSH `authorized_keys` content** — AWS has no API for this. `scan_ec2_key_pairs` only lists the EC2 key-pair name/fingerprint registered at instance launch (`ec2:DescribeKeyPairs`), not what's actually in `~/.ssh/authorized_keys` on a running instance. Same category of gap as Bitbucket's account SSH keys.
- **Inline and customer-managed policy document parsing** — `scan_iam_policy_bindings` flags known high-risk *AWS-managed* policies (`AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess`) but does not parse inline or customer-managed policy JSON documents for an equivalent `"Action": "*", "Resource": "*"` statement. Such a policy always shows as `info` severity (tagged `inline` if applicable) even if it happens to grant full access.

## Key age thresholds

`aws.key_age_warn_days` / `aws.key_age_critical_days` in `config/soc2.config.yaml` control when an IAM access key is flagged `high`/`critical` for being unrotated - same mechanism and same defaults (90 / 180 days) as the GCP service-account key check.

## Root account, S3, and password-staleness severity rules

- **Root account** (`scan_root_account_security`): `critical` if MFA is disabled, or if the root account still has access keys present (root should never have long-lived programmatic credentials) - either alone is enough to flag the whole account `critical`.
- **S3 buckets** (`scan_s3_bucket_exposure`): `critical` if the bucket is public via ACL or bucket policy (S3's own computed `IsPublic` flag, not hand-parsed policy JSON); `medium` if not public but Block Public Access isn't fully enabled as a backstop; `info` otherwise.
- **IAM Users password staleness**: the Markdown report's "Password Last Used" column renders in red when a console password was last used more than 180 days ago (`PASSWORD_STALE_DAYS` in `report_writer.py`) - `never` is left unstyled, since it usually just means the user has no console access at all (see the separate Console Access column), not a stale credential.
