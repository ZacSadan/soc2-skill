"""AWS provider scanner: IAM users/keys, IAM roles, IAM policy bindings
(managed + inline, across users/roles/groups), root account security
(MFA/access keys), IAM Access Advisor (service-last-accessed, best-effort),
EC2 security groups, EC2 key pairs, S3 public-bucket exposure, API Gateway
API keys, cross-region resource inventory via Resource Explorer
(best-effort, needs ViewOnlyAccess), and best-effort Security Hub /
GuardDuty / Access Analyzer findings.

IAM, S3 (list_buckets), and the root account summary are global/account-wide
and scanned once regardless of region. EC2/API Gateway/Security Hub/
GuardDuty/Access Analyzer are region-scoped - this scanner only covers the
single configured region (`aws.region`, default us-east-1), not every
region in the account.

Every check is independently try/excepted so one failing or disabled check
never aborts the rest of the scan - failures are recorded in `errors` with a
reason string instead, same resilience pattern as the GCP/Bitbucket scanners.
"""
import csv
import datetime
import os
import time

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from common.redact import register_secret

DEFAULT_REGION = "us-east-1"

# Binding to one of these (or having console access with no MFA, or a role
# with a "*" trust principal) makes the entitled principal a de facto
# account admin / public entry point - the AWS analog of HIGH_RISK_ROLES in
# the GCP scanner. Inline policy documents are not parsed for equivalent
# "Action: *, Resource: *" statements - out of scope for this pass.
HIGH_RISK_MANAGED_POLICIES = {"AdministratorAccess", "PowerUserAccess", "IAMFullAccess"}


def _client_error_reason(e):
    try:
        return e.response["Error"]["Code"]
    except Exception:  # noqa: BLE001 - fall back to a generic reason if the shape is unexpected
        return "ERROR"


def _age_days(dt):
    if dt is None:
        return None
    return (datetime.datetime.now(datetime.timezone.utc) - dt).days


def _iso(dt):
    return dt.isoformat() if dt else None


def _load_credentials(creds_path):
    """Reads the CSV downloaded from IAM > Users > Security credentials >
    Create access key. Registers both fields with the redaction layer -
    the secret key is sensitive; the access key ID isn't secret by itself
    but is still a stable identifier worth scrubbing on general principle."""
    with open(creds_path, "r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"No credential rows found in {creds_path}")
    row = rows[0]
    access_key_id = row.get("Access key ID") or row.get("AccessKeyId")
    secret_access_key = row.get("Secret access key") or row.get("SecretAccessKey")
    if not access_key_id or not secret_access_key:
        raise ValueError(f"Could not find 'Access key ID'/'Secret access key' columns in {creds_path}")
    register_secret(secret_access_key)
    register_secret(access_key_id)
    return access_key_id, secret_access_key


def _policy_allows_any_principal(doc):
    if not isinstance(doc, dict):
        return False
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            if aws_principal == "*" or (isinstance(aws_principal, list) and "*" in aws_principal):
                return True
    return False


def scan_iam_users_and_keys(iam, key_age_warn_days, key_age_critical_days, errors):
    resources = []
    try:
        users = []
        for page in iam.get_paginator("list_users").paginate():
            users.extend(page.get("Users", []))
    except ClientError as e:
        errors.append({"check": "iam_users", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for user in users:
        user_name = user["UserName"]

        try:
            mfa_devices = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
        except ClientError as e:
            errors.append({"check": f"iam_mfa:{user_name}", "reason": _client_error_reason(e), "detail": str(e)})
            mfa_devices = []

        try:
            iam.get_login_profile(UserName=user_name)
            has_console_access = True
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                errors.append({"check": f"iam_login_profile:{user_name}", "reason": _client_error_reason(e), "detail": str(e)})
            has_console_access = False

        severity = "high" if has_console_access and not mfa_devices else "info"
        resources.append({
            "type": "aws.iam.user",
            "id": f"user:{user_name}",
            "attributes": {
                "user_name": user_name,
                "arn": user.get("Arn"),
                "create_date": _iso(user.get("CreateDate")),
                "password_last_used": _iso(user.get("PasswordLastUsed")),
                "has_console_access": has_console_access,
                "mfa_enabled": bool(mfa_devices),
            },
            "severity": severity,
            "tags": ["iam", "user"] + (["no_mfa"] if severity == "high" else []),
        })

        try:
            keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        except ClientError as e:
            errors.append({"check": f"iam_access_keys:{user_name}", "reason": _client_error_reason(e), "detail": str(e)})
            keys = []

        for key in keys:
            key_id = key["AccessKeyId"]
            age = _age_days(key.get("CreateDate"))
            try:
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {})
            except ClientError as e:
                errors.append({"check": f"iam_key_last_used:{key_id}", "reason": _client_error_reason(e), "detail": str(e)})
                last_used = {}

            severity = "info"
            if key.get("Status") == "Active" and age is not None:
                if age >= key_age_critical_days:
                    severity = "critical"
                elif age >= key_age_warn_days:
                    severity = "high"

            resources.append({
                "type": "aws.iam.access_key",
                "id": f"access_key:{key_id}",
                "attributes": {
                    "user_name": user_name,
                    "key_id": key_id,
                    "status": key.get("Status"),
                    "age_days": age,
                    "created": _iso(key.get("CreateDate")),
                    "last_used_date": _iso(last_used.get("LastUsedDate")),
                    "last_used_service": last_used.get("ServiceName"),
                    "last_used_region": last_used.get("Region"),
                },
                "severity": severity,
                "tags": ["iam", "access_key"] + (["unrotated"] if severity in ("high", "critical") else []),
            })

    return resources


def scan_iam_roles(iam, errors):
    resources = []
    try:
        roles = []
        for page in iam.get_paginator("list_roles").paginate():
            roles.extend(page.get("Roles", []))
    except ClientError as e:
        errors.append({"check": "iam_roles", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for role in roles:
        role_name = role["RoleName"]
        is_public_trust = _policy_allows_any_principal(role.get("AssumeRolePolicyDocument") or {})
        is_service_linked = (role.get("Path") or "").startswith("/aws-service-role/")
        resources.append({
            "type": "aws.iam.role",
            "id": f"role:{role_name}",
            "attributes": {
                "role_name": role_name,
                "arn": role.get("Arn"),
                "create_date": _iso(role.get("CreateDate")),
                "is_service_linked": is_service_linked,
                "trust_policy_public": is_public_trust,
            },
            "severity": "critical" if is_public_trust else "info",
            "tags": ["iam", "role"] + (["public_trust"] if is_public_trust else []),
        })
    return resources


def scan_iam_policy_bindings(iam, errors):
    """Mirrors the GCP IAM binding check: every managed-policy attachment
    and inline policy on every user, role, and group, so "who can do what"
    doesn't require cross-referencing 3 separate console pages."""
    resources = []

    def emit(principal_type, principal_name, policy_name, policy_arn, is_inline):
        severity = "high" if policy_name in HIGH_RISK_MANAGED_POLICIES else "info"
        resources.append({
            "type": "aws.iam.binding",
            "id": f"binding:{principal_type}:{principal_name}:{policy_name}",
            "attributes": {
                "principal": principal_name, "principal_type": principal_type,
                "policy_name": policy_name, "policy_arn": policy_arn,
            },
            "severity": severity,
            "tags": ["iam", "binding"] + (["inline"] if is_inline else []) + (["admin"] if severity == "high" else []),
        })

    try:
        users = []
        for page in iam.get_paginator("list_users").paginate():
            users.extend(page.get("Users", []))
        for user in users:
            name = user["UserName"]
            for p in iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", []):
                emit("user", name, p["PolicyName"], p["PolicyArn"], is_inline=False)
            for policy_name in iam.list_user_policies(UserName=name).get("PolicyNames", []):
                emit("user", name, policy_name, None, is_inline=True)
    except ClientError as e:
        errors.append({"check": "iam_user_policies", "reason": _client_error_reason(e), "detail": str(e)})

    try:
        roles = []
        for page in iam.get_paginator("list_roles").paginate():
            roles.extend(page.get("Roles", []))
        for role in roles:
            name = role["RoleName"]
            if (role.get("Path") or "").startswith("/aws-service-role/"):
                continue  # AWS-managed service-linked roles - not actionable, would just be noise
            for p in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
                emit("role", name, p["PolicyName"], p["PolicyArn"], is_inline=False)
            for policy_name in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                emit("role", name, policy_name, None, is_inline=True)
    except ClientError as e:
        errors.append({"check": "iam_role_policies", "reason": _client_error_reason(e), "detail": str(e)})

    try:
        groups = []
        for page in iam.get_paginator("list_groups").paginate():
            groups.extend(page.get("Groups", []))
        for group in groups:
            name = group["GroupName"]
            for p in iam.list_attached_group_policies(GroupName=name).get("AttachedPolicies", []):
                emit("group", name, p["PolicyName"], p["PolicyArn"], is_inline=False)
            for policy_name in iam.list_group_policies(GroupName=name).get("PolicyNames", []):
                emit("group", name, policy_name, None, is_inline=True)
    except ClientError as e:
        errors.append({"check": "iam_group_policies", "reason": _client_error_reason(e), "detail": str(e)})

    return resources


def scan_root_account_security(iam, errors):
    """The root account has no GCP equivalent worth mirroring - it's an
    AWS-specific, single highest-value check: a compromised root account
    (no MFA, or worse, still has long-lived access keys) is catastrophic
    and unrecoverable-by-policy, since root can't be restricted by any IAM
    policy. One global call (`iam:GetAccountSummary`, already covered by
    SecurityAudit) covers the whole account - no per-user looping."""
    resources = []
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
    except ClientError as e:
        errors.append({"check": "account_summary", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    mfa_enabled = bool(summary.get("AccountMFAEnabled"))
    access_keys_present = bool(summary.get("AccountAccessKeysPresent"))
    signing_certs_present = bool(summary.get("AccountSigningCertificatesPresent"))

    severity = "info"
    tags = ["iam", "root_account"]
    if not mfa_enabled:
        severity = "critical"
        tags.append("no_mfa")
    if access_keys_present:
        severity = "critical"
        tags.append("access_keys_present")

    resources.append({
        "type": "aws.iam.root_account",
        "id": "root_account",
        "attributes": {
            "mfa_enabled": mfa_enabled,
            "access_keys_present": access_keys_present,
            "signing_certificates_present": signing_certs_present,
        },
        "severity": severity,
        "tags": tags,
    })
    return resources


def _fmt_ip_permission(perm):
    protocol = perm.get("IpProtocol")
    if protocol == "-1":
        port_desc = "all"
    elif perm.get("FromPort") is None:
        port_desc = protocol
    elif perm.get("FromPort") == perm.get("ToPort"):
        port_desc = f"{protocol}:{perm['FromPort']}"
    else:
        port_desc = f"{protocol}:{perm['FromPort']}-{perm['ToPort']}"
    sources = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
    sources += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
    sources = [s for s in sources if s] or ["sg/prefix-list ref"]
    return f"{port_desc} from {', '.join(sources)}"


def scan_security_groups(ec2, sensitive_ports, errors):
    resources = []
    sensitive_ports = {int(p) for p in sensitive_ports}
    try:
        sgs = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            sgs.extend(page.get("SecurityGroups", []))
    except ClientError as e:
        errors.append({"check": "security_groups", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for sg in sgs:
        is_public = False
        exposes_sensitive_port = False
        for perm in sg.get("IpPermissions", []):
            is_open = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or \
                any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if not is_open:
                continue
            is_public = True
            from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
            if perm.get("IpProtocol") == "-1" or (
                from_port is not None and to_port is not None and any(from_port <= p <= to_port for p in sensitive_ports)
            ):
                exposes_sensitive_port = True

        severity = "info"
        if is_public:
            severity = "critical" if exposes_sensitive_port else "high"

        resources.append({
            "type": "aws.ec2.security_group",
            "id": f"sg:{sg['GroupId']}",
            "attributes": {
                "group_id": sg["GroupId"], "group_name": sg.get("GroupName"),
                "vpc_id": sg.get("VpcId"), "description": sg.get("Description"),
                "ingress_rules": [_fmt_ip_permission(p) for p in sg.get("IpPermissions", [])],
            },
            "severity": severity,
            "tags": ["network", "security_group"] + (["public-exposure"] if is_public else []),
        })
    return resources


def scan_ec2_key_pairs(ec2, errors):
    """EC2 key pairs - AWS's closest equivalent to GCP's SSH key metadata,
    but narrower: this only lists the key-pair name/fingerprint registered
    at instance launch, not per-instance authorized_keys content (AWS has
    no API for that, same category of gap as Bitbucket account SSH keys)."""
    resources = []
    try:
        key_pairs = ec2.describe_key_pairs().get("KeyPairs", [])
    except ClientError as e:
        errors.append({"check": "ec2_key_pairs", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for kp in key_pairs:
        resources.append({
            "type": "aws.ec2.key_pair",
            "id": f"key_pair:{kp.get('KeyPairId')}",
            "attributes": {
                "key_name": kp.get("KeyName"), "key_pair_id": kp.get("KeyPairId"),
                "key_type": kp.get("KeyType"), "fingerprint": kp.get("KeyFingerprint"),
                "create_time": _iso(kp.get("CreateTime")),
            },
            "severity": "info",
            "tags": ["network", "ssh_key"],
        })
    return resources


def scan_api_gateway_keys(apigateway, errors):
    resources = []
    try:
        keys = []
        position = None
        while True:
            kwargs = {"includeValues": False}
            if position:
                kwargs["position"] = position
            resp = apigateway.get_api_keys(**kwargs)
            keys.extend(resp.get("items", []))
            position = resp.get("position")
            if not position:
                break
    except ClientError as e:
        errors.append({"check": "api_gateway_keys", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for key in keys:
        resources.append({
            "type": "aws.apigateway.key",
            "id": f"api_key:{key.get('id')}",
            "attributes": {
                "name": key.get("name"), "enabled": key.get("enabled"),
                "created_date": _iso(key.get("createdDate")),
                "stage_keys": key.get("stageKeys", []),
            },
            "severity": "info",
            "tags": ["iam", "api_key"],
        })
    return resources


def scan_s3_bucket_exposure(s3, errors):
    """S3 public-bucket exposure - the AWS analog of the GCS
    PUBLIC_BUCKET_ACL findings that dominated the GCP Security Command
    Center chapter this session. Checks 3 independent public-exposure
    surfaces per bucket: the ACL grants, the bucket policy (via S3's own
    computed IsPublic flag rather than parsing policy JSON by hand), and
    whether Block Public Access is fully enabled as a backstop. `list_buckets`
    is a true global operation (returns every bucket regardless of region);
    the per-bucket calls below are issued against the default configured
    region's endpoint, which S3 handles transparently for the read-only
    operations used here."""
    resources = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        errors.append({"check": "s3_list_buckets", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for bucket in buckets:
        name = bucket["Name"]

        is_public_acl = False
        try:
            for grant in s3.get_bucket_acl(Bucket=name).get("Grants", []):
                uri = (grant.get("Grantee") or {}).get("URI", "")
                if uri.endswith("/global/AllUsers") or uri.endswith("/global/AuthenticatedUsers"):
                    is_public_acl = True
        except ClientError as e:
            errors.append({"check": f"s3_bucket_acl:{name}", "reason": _client_error_reason(e), "detail": str(e)})

        is_public_policy = False
        try:
            status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            is_public_policy = bool(status.get("IsPublic"))
        except ClientError as e:
            if _client_error_reason(e) != "NoSuchBucketPolicy":
                errors.append({"check": f"s3_bucket_policy_status:{name}", "reason": _client_error_reason(e), "detail": str(e)})

        block_public_access_enabled = False
        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            block_public_access_enabled = all(pab.get(k, False) for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
            ))
        except ClientError as e:
            if _client_error_reason(e) != "NoSuchPublicAccessBlockConfiguration":
                errors.append({"check": f"s3_public_access_block:{name}", "reason": _client_error_reason(e), "detail": str(e)})

        is_public = is_public_acl or is_public_policy
        severity = "critical" if is_public else ("medium" if not block_public_access_enabled else "info")

        resources.append({
            "type": "aws.s3.bucket",
            "id": f"bucket:{name}",
            "attributes": {
                "bucket_name": name,
                "is_public_acl": is_public_acl,
                "is_public_policy": is_public_policy,
                "block_public_access_enabled": block_public_access_enabled,
            },
            "severity": severity,
            "tags": ["storage", "s3_bucket"] + (["public"] if is_public else []),
        })
    return resources


def scan_security_hub_findings(securityhub, errors):
    """Best-effort, same posture as GCP SCC: Security Hub often isn't
    enabled, which surfaces as a skipped check rather than a scan failure."""
    resources = []
    try:
        findings = []
        next_token = None
        while True:
            kwargs = {"Filters": {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}, "MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = securityhub.get_findings(**kwargs)
            findings.extend(resp.get("Findings", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
    except ClientError as e:
        errors.append({"check": "security_hub_findings", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for f in findings:
        severity = (f.get("Severity", {}).get("Label") or "INFORMATIONAL").lower()
        if severity == "informational":
            severity = "info"
        resources.append({
            "type": "aws.securityhub.finding",
            "id": f"finding:{f.get('Id')}",
            "attributes": {
                "title": f.get("Title"),
                "resource_ids": [r.get("Id") for r in f.get("Resources", [])],
                "workflow_state": (f.get("Workflow") or {}).get("Status"),
                "compliance_status": (f.get("Compliance") or {}).get("Status"),
            },
            "severity": severity,
            "tags": ["securityhub"],
        })
    return resources


def scan_access_analyzer_findings(accessanalyzer, errors):
    """Best-effort, same posture as GCP IAM Recommender: no analyzer
    configured surfaces as an empty list plus a skipped check, not a crash."""
    resources = []
    try:
        analyzers = accessanalyzer.list_analyzers().get("analyzers", [])
    except ClientError as e:
        errors.append({"check": "access_analyzer", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for analyzer in analyzers:
        try:
            findings = []
            next_token = None
            while True:
                kwargs = {"analyzerArn": analyzer["arn"]}
                if next_token:
                    kwargs["nextToken"] = next_token
                resp = accessanalyzer.list_findings(**kwargs)
                findings.extend(resp.get("findings", []))
                next_token = resp.get("nextToken")
                if not next_token:
                    break
        except ClientError as e:
            errors.append({"check": f"access_analyzer_findings:{analyzer.get('name')}", "reason": _client_error_reason(e), "detail": str(e)})
            continue

        for finding in findings:
            if finding.get("status") != "ACTIVE":
                continue
            is_public = bool(finding.get("isPublic"))
            resources.append({
                "type": "aws.accessanalyzer.finding",
                "id": f"finding:{finding.get('id')}",
                "attributes": {
                    "resource": finding.get("resource"), "resource_type": finding.get("resourceType"),
                    "is_public": is_public, "condition": finding.get("condition"),
                },
                "severity": "critical" if is_public else "medium",
                "tags": ["accessanalyzer"] + (["public"] if is_public else []),
            })
    return resources


def scan_guardduty_findings(guardduty, errors):
    """Best-effort, same posture as Security Hub/SCC: no detector enabled
    in this region surfaces as an empty list plus a skipped check."""
    resources = []
    try:
        detector_ids = guardduty.list_detectors().get("DetectorIds", [])
    except ClientError as e:
        errors.append({"check": "guardduty_detectors", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for detector_id in detector_ids:
        try:
            finding_ids = []
            next_token = None
            while True:
                kwargs = {
                    "DetectorId": detector_id,
                    "FindingCriteria": {"Criterion": {"service.archived": {"Eq": ["false"]}}},
                    "MaxResults": 50,
                }
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = guardduty.list_findings(**kwargs)
                finding_ids.extend(resp.get("FindingIds", []))
                next_token = resp.get("NextToken")
                if not next_token:
                    break
        except ClientError as e:
            errors.append({"check": f"guardduty_list_findings:{detector_id}", "reason": _client_error_reason(e), "detail": str(e)})
            continue

        # GetFindings caps out at 50 IDs per call.
        for i in range(0, len(finding_ids), 50):
            batch = finding_ids[i:i + 50]
            try:
                details = guardduty.get_findings(DetectorId=detector_id, FindingIds=batch).get("Findings", [])
            except ClientError as e:
                errors.append({"check": f"guardduty_get_findings:{detector_id}", "reason": _client_error_reason(e), "detail": str(e)})
                continue

            for f in details:
                # GuardDuty severity bands: Low 1.0-3.9, Medium 4.0-6.9, High 7.0-8.9.
                score = f.get("Severity", 0)
                severity = "high" if score >= 7.0 else "medium" if score >= 4.0 else "low"
                resources.append({
                    "type": "aws.guardduty.finding",
                    "id": f"finding:{f.get('Id')}",
                    "attributes": {
                        "title": f.get("Title"),
                        "finding_type": f.get("Type"),
                        "severity_score": score,
                        "resource_type": (f.get("Resource") or {}).get("ResourceType"),
                        "count": (f.get("Service") or {}).get("Count"),
                    },
                    "severity": severity,
                    "tags": ["guardduty"],
                })
    return resources


def scan_iam_access_advisor(iam, errors):
    """Best-effort IAM Access Advisor (service-last-accessed data) - the
    AWS analog of the GCP service-account usage-metrics check. Access
    Advisor jobs are asynchronous (generate, then poll for completion), so
    this only covers IAM Users (not roles, to bound total scan time) and
    gives up on a given user after a handful of short polls rather than
    blocking the whole scan on one slow job - AWS docs say jobs normally
    complete within seconds, so a stalled one is treated as a skip, not
    worth failing the run over."""
    resources = []
    try:
        users = []
        for page in iam.get_paginator("list_users").paginate():
            users.extend(page.get("Users", []))
    except ClientError as e:
        errors.append({"check": "access_advisor_list_users", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for user in users:
        user_name = user["UserName"]
        try:
            job_id = iam.generate_service_last_accessed_details(Arn=user["Arn"]).get("JobId")
        except ClientError as e:
            errors.append({"check": f"access_advisor_generate:{user_name}", "reason": _client_error_reason(e), "detail": str(e)})
            continue

        services = None
        for _ in range(5):
            try:
                resp = iam.get_service_last_accessed_details(JobId=job_id)
            except ClientError as e:
                errors.append({"check": f"access_advisor_get:{user_name}", "reason": _client_error_reason(e), "detail": str(e)})
                break
            if resp.get("JobStatus") == "COMPLETED":
                services = resp.get("ServicesLastAccessed", [])
                break
            if resp.get("JobStatus") == "FAILED":
                errors.append({"check": f"access_advisor_get:{user_name}", "reason": "JOB_FAILED", "detail": resp.get("JobCompletionDate", "")})
                break
            time.sleep(1)

        if services is None:
            continue  # job never completed in time - skip this user rather than report a false "no activity"

        used = [s for s in services if s.get("LastAuthenticated")]
        most_recent = max((s["LastAuthenticated"] for s in used), default=None)

        resources.append({
            "type": "aws.iam.access_advisor",
            "id": f"access_advisor:{user_name}",
            "attributes": {
                "user_name": user_name,
                "last_activity": _iso(most_recent),
                "services_used_count": len(used),
                "services_granted_count": len(services),
            },
            "severity": "medium" if services and not used else "info",
            "tags": ["iam", "access_advisor"] + (["inactive"] if services and not used else []),
        })
    return resources


def scan_resource_explorer_inventory(resourceexplorer, errors):
    """Cross-region resource inventory via AWS Resource Explorer - the one
    thing in this scanner that specifically needs `ViewOnlyAccess`
    (`resource-explorer-2:*`), since `SecurityAudit` doesn't grant it at
    all. Resource Explorer is opt-in and needs an admin to turn on
    indexing first, so an account/region without it configured degrades to
    a skipped check, not a crash - same best-effort posture as Security
    Hub/GuardDuty/Access Analyzer. When it *is* enabled, this is the only
    check in the scanner that sees resources outside the single configured
    `aws.region` - it reports what exists in every indexed region, as a
    per-(resource type, region) count, so the report can flag "there are
    resources in regions this scan didn't otherwise look at" without
    requiring a full multi-region rescan."""
    resources = []
    try:
        view_arn = resourceexplorer.get_default_view().get("ViewArn")
    except ClientError as e:
        errors.append({"check": "resource_explorer_view", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    if not view_arn:
        return resources  # no default view configured - nothing indexed, not an error

    by_type_region = {}
    try:
        next_token = None
        while True:
            kwargs = {"QueryString": "", "ViewArn": view_arn, "MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = resourceexplorer.search(**kwargs)
            for r in resp.get("Resources", []):
                key = (r.get("ResourceType"), r.get("Region"))
                by_type_region[key] = by_type_region.get(key, 0) + 1
            next_token = resp.get("NextToken")
            if not next_token:
                break
    except ClientError as e:
        errors.append({"check": "resource_explorer_search", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for (resource_type, region), count in by_type_region.items():
        resources.append({
            "type": "aws.resourceexplorer.resource_count",
            "id": f"resource_count:{region}:{resource_type}",
            "attributes": {"resource_type": resource_type, "region": region, "count": count},
            "severity": "info",
            "tags": ["resourceexplorer"],
        })
    return resources


def scan_cloudtrail_config(cloudtrail, errors):
    """CloudTrail is AWS's audit-log backbone - the SOC2-relevant question
    isn't just "does a trail exist" but whether it's actually logging,
    covers all regions, and has log file validation (tamper detection)
    enabled. No trails at all is flagged critical (no audit trail exists);
    a trail that exists but isn't actively logging is equally critical."""
    resources = []
    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
    except ClientError as e:
        errors.append({"check": "cloudtrail_trails", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    if not trails:
        resources.append({
            "type": "aws.cloudtrail.trail",
            "id": "cloudtrail:none",
            "attributes": {"name": None, "is_logging": False},
            "severity": "critical",
            "tags": ["cloudtrail", "no-trail"],
        })
        return resources

    for trail in trails:
        name = trail.get("Name")
        trail_arn = trail.get("TrailARN")
        try:
            status = cloudtrail.get_trail_status(Name=trail_arn).get("IsLogging", False)
        except ClientError as e:
            errors.append({"check": f"cloudtrail_status:{name}", "reason": _client_error_reason(e), "detail": str(e)})
            status = None

        is_multi_region = bool(trail.get("IsMultiRegionTrail"))
        log_validation = bool(trail.get("LogFileValidationEnabled"))

        severity = "info"
        tags = ["cloudtrail"]
        if status is False:
            severity = "critical"
            tags.append("not-logging")
        elif not is_multi_region:
            severity = "medium"
            tags.append("single-region")
        elif not log_validation:
            severity = "medium"
            tags.append("no-log-validation")

        resources.append({
            "type": "aws.cloudtrail.trail",
            "id": f"cloudtrail:{name}",
            "attributes": {
                "name": name,
                "is_logging": status,
                "is_multi_region": is_multi_region,
                "log_file_validation_enabled": log_validation,
                "s3_bucket": trail.get("S3BucketName"),
            },
            "severity": severity,
            "tags": tags,
        })
    return resources


def scan_config_recorder(configservice, errors):
    """AWS Config's configuration recorder - no recorder at all, or one
    that's provisioned but not actively recording, means no continuous
    resource-configuration history exists for the account/region."""
    resources = []
    try:
        recorders = configservice.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except ClientError as e:
        errors.append({"check": "config_recorders", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    if not recorders:
        resources.append({
            "type": "aws.config.recorder",
            "id": "config_recorder:none",
            "attributes": {"name": None, "recording": False},
            "severity": "medium",
            "tags": ["config", "no-recorder"],
        })
        return resources

    try:
        statuses = {s["name"]: s for s in configservice.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])}
    except ClientError as e:
        errors.append({"check": "config_recorder_status", "reason": _client_error_reason(e), "detail": str(e)})
        statuses = {}

    for recorder in recorders:
        name = recorder.get("name")
        status = statuses.get(name, {})
        recording = bool(status.get("recording"))
        recording_group = recorder.get("recordingGroup", {})
        resources.append({
            "type": "aws.config.recorder",
            "id": f"config_recorder:{name}",
            "attributes": {
                "name": name,
                "recording": recording,
                "all_supported": recording_group.get("allSupported"),
                "include_global_resource_types": recording_group.get("includeGlobalResourceTypes"),
                "last_status": status.get("lastStatus"),
            },
            "severity": "high" if not recording else "info",
            "tags": ["config"] + ([] if recording else ["not-recording"]),
        })
    return resources


def scan_iam_password_policy(iam, errors):
    """Account-wide IAM password policy - or the lack of one, which leaves
    AWS's very permissive defaults (no minimum length, no complexity
    requirements) in effect for every IAM user with console access."""
    resources = []
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except ClientError as e:
        if _client_error_reason(e) == "NoSuchEntity":
            resources.append({
                "type": "aws.iam.password_policy",
                "id": "password_policy",
                "attributes": {"configured": False},
                "severity": "high",
                "tags": ["iam", "no-password-policy"],
            })
            return resources
        errors.append({"check": "iam_password_policy", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    min_length = policy.get("MinimumPasswordLength", 0)
    requires_complexity = policy.get("RequireSymbols") and policy.get("RequireNumbers") and \
        policy.get("RequireUppercaseCharacters") and policy.get("RequireLowercaseCharacters")
    is_weak = min_length < 14 or not requires_complexity

    resources.append({
        "type": "aws.iam.password_policy",
        "id": "password_policy",
        "attributes": {
            "configured": True,
            "minimum_length": min_length,
            "require_symbols": policy.get("RequireSymbols"),
            "require_numbers": policy.get("RequireNumbers"),
            "require_uppercase": policy.get("RequireUppercaseCharacters"),
            "require_lowercase": policy.get("RequireLowercaseCharacters"),
            "max_password_age": policy.get("MaxPasswordAge"),
            "password_reuse_prevention": policy.get("PasswordReusePrevention"),
        },
        "severity": "medium" if is_weak else "info",
        "tags": ["iam"] + (["weak-policy"] if is_weak else []),
    })
    return resources


def scan_kms_key_rotation(kms, errors):
    """Customer-managed KMS keys with automatic rotation disabled - the AWS
    analog of the GCP Cloud KMS rotation check. AWS-managed keys (KeyManager
    == "AWS") are skipped since the account doesn't control their rotation
    policy at all."""
    resources = []
    try:
        key_ids = []
        for page in kms.get_paginator("list_keys").paginate():
            key_ids.extend(k["KeyId"] for k in page.get("Keys", []))
    except ClientError as e:
        errors.append({"check": "kms_list_keys", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for key_id in key_ids:
        try:
            meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
        except ClientError as e:
            errors.append({"check": f"kms_describe_key:{key_id}", "reason": _client_error_reason(e), "detail": str(e)})
            continue

        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
            continue  # AWS-managed, pending-deletion, or disabled keys aren't actionable here

        rotation_enabled = None
        if meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT":
            try:
                rotation_enabled = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled")
            except ClientError as e:
                errors.append({"check": f"kms_rotation_status:{key_id}", "reason": _client_error_reason(e), "detail": str(e)})

        resources.append({
            "type": "aws.kms.key",
            "id": f"kms_key:{key_id}",
            "attributes": {
                "key_id": key_id,
                "description": meta.get("Description"),
                "key_spec": meta.get("KeySpec"),
                "rotation_enabled": rotation_enabled,
            },
            "severity": "high" if rotation_enabled is False else "info",
            "tags": ["kms"] + (["no-rotation"] if rotation_enabled is False else []),
        })
    return resources


def scan_rds_instances(rds, errors):
    """RDS instance exposure - the AWS analog of the GCP Cloud SQL check:
    flags publicly-accessible instances and unencrypted storage."""
    resources = []
    try:
        instances = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            instances.extend(page.get("DBInstances", []))
    except ClientError as e:
        errors.append({"check": "rds_instances", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    for inst in instances:
        identifier = inst.get("DBInstanceIdentifier")
        publicly_accessible = bool(inst.get("PubliclyAccessible"))
        storage_encrypted = bool(inst.get("StorageEncrypted"))

        severity = "info"
        tags = ["rds"]
        if publicly_accessible:
            severity = "critical"
            tags.append("public-exposure")
        elif not storage_encrypted:
            severity = "medium"
            tags.append("unencrypted")

        resources.append({
            "type": "aws.rds.instance",
            "id": f"rds_instance:{identifier}",
            "attributes": {
                "identifier": identifier,
                "engine": inst.get("Engine"),
                "publicly_accessible": publicly_accessible,
                "storage_encrypted": storage_encrypted,
            },
            "severity": severity,
            "tags": tags,
        })
    return resources


def scan_ebs_default_encryption(ec2, errors):
    """EBS encryption-by-default is a single per-region account setting -
    when off, every newly-created volume that doesn't explicitly request
    encryption is created unencrypted."""
    resources = []
    try:
        enabled = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
    except ClientError as e:
        errors.append({"check": "ebs_default_encryption", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    resources.append({
        "type": "aws.ec2.ebs_default_encryption",
        "id": "ebs_default_encryption",
        "attributes": {"enabled": enabled},
        "severity": "medium" if not enabled else "info",
        "tags": ["ec2"] + ([] if enabled else ["disabled"]),
    })
    return resources


def scan_vpc_flow_logs(ec2, errors):
    """Flags VPCs with no active Flow Log - without one, there's no record
    of network traffic to investigate after an incident."""
    resources = []
    try:
        vpcs = []
        for page in ec2.get_paginator("describe_vpcs").paginate():
            vpcs.extend(page.get("Vpcs", []))
    except ClientError as e:
        errors.append({"check": "vpc_list", "reason": _client_error_reason(e), "detail": str(e)})
        return resources

    try:
        flow_logs = []
        for page in ec2.get_paginator("describe_flow_logs").paginate():
            flow_logs.extend(page.get("FlowLogs", []))
    except ClientError as e:
        errors.append({"check": "vpc_flow_logs", "reason": _client_error_reason(e), "detail": str(e)})
        flow_logs = []

    vpcs_with_active_flow_logs = {
        fl.get("ResourceId") for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"
    }

    for vpc in vpcs:
        vpc_id = vpc.get("VpcId")
        has_flow_log = vpc_id in vpcs_with_active_flow_logs
        resources.append({
            "type": "aws.ec2.vpc",
            "id": f"vpc:{vpc_id}",
            "attributes": {"vpc_id": vpc_id, "is_default": vpc.get("IsDefault"), "has_flow_log": has_flow_log},
            "severity": "medium" if not has_flow_log else "info",
            "tags": ["network", "vpc"] + ([] if has_flow_log else ["no-flow-log"]),
        })
    return resources


def scan(config, errors):
    """Returns (resources, status)."""
    aws_cfg = config["aws"]
    creds_path = aws_cfg["_creds_path_resolved"]
    if not os.path.exists(creds_path):
        errors.append({"check": "aws_auth", "reason": "MISSING_CREDENTIALS", "detail": f"No credentials file at {creds_path}"})
        return [], "error"

    try:
        access_key_id, secret_access_key = _load_credentials(creds_path)
    except ValueError as e:
        errors.append({"check": "aws_auth", "reason": "INVALID_CREDENTIALS_FILE", "detail": str(e)})
        return [], "error"

    region = aws_cfg.get("region", DEFAULT_REGION)
    session = boto3.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)

    try:
        session.client("sts").get_caller_identity()
    except (ClientError, NoCredentialsError) as e:
        reason = _client_error_reason(e) if isinstance(e, ClientError) else "NO_CREDENTIALS"
        errors.append({"check": "aws_auth", "reason": reason, "detail": str(e)})
        return [], "error"

    checks_cfg = aws_cfg.get("checks", {})
    resources = []

    iam = session.client("iam")
    if checks_cfg.get("iam_users", True):
        resources += scan_iam_users_and_keys(
            iam, aws_cfg.get("key_age_warn_days", 90), aws_cfg.get("key_age_critical_days", 180), errors
        )
    if checks_cfg.get("iam_roles", True):
        resources += scan_iam_roles(iam, errors)
    if checks_cfg.get("iam_bindings", True):
        resources += scan_iam_policy_bindings(iam, errors)
    if checks_cfg.get("root_account", True):
        resources += scan_root_account_security(iam, errors)
    if checks_cfg.get("access_advisor", True):
        resources += scan_iam_access_advisor(iam, errors)
    if checks_cfg.get("password_policy", True):
        resources += scan_iam_password_policy(iam, errors)

    ec2 = session.client("ec2")
    if checks_cfg.get("security_groups", True):
        resources += scan_security_groups(ec2, aws_cfg.get("sensitive_ports", [22, 3389, 3306, 5432]), errors)
    if checks_cfg.get("ec2_key_pairs", True):
        resources += scan_ec2_key_pairs(ec2, errors)
    if checks_cfg.get("ebs_default_encryption", True):
        resources += scan_ebs_default_encryption(ec2, errors)
    if checks_cfg.get("vpc_flow_logs", True):
        resources += scan_vpc_flow_logs(ec2, errors)

    if checks_cfg.get("s3_bucket_exposure", True):
        resources += scan_s3_bucket_exposure(session.client("s3"), errors)
    if checks_cfg.get("api_gateway_keys", True):
        resources += scan_api_gateway_keys(session.client("apigateway"), errors)
    if checks_cfg.get("security_hub", True):
        resources += scan_security_hub_findings(session.client("securityhub"), errors)
    if checks_cfg.get("access_analyzer", True):
        resources += scan_access_analyzer_findings(session.client("accessanalyzer"), errors)
    if checks_cfg.get("guardduty", True):
        resources += scan_guardduty_findings(session.client("guardduty"), errors)
    if checks_cfg.get("resource_explorer", True):
        resources += scan_resource_explorer_inventory(session.client("resource-explorer-2"), errors)
    if checks_cfg.get("cloudtrail", True):
        resources += scan_cloudtrail_config(session.client("cloudtrail"), errors)
    if checks_cfg.get("config_recorder", True):
        resources += scan_config_recorder(session.client("config"), errors)
    if checks_cfg.get("kms_key_rotation", True):
        resources += scan_kms_key_rotation(session.client("kms"), errors)
    if checks_cfg.get("rds_instances", True):
        resources += scan_rds_instances(session.client("rds"), errors)

    status = "ok" if not errors else "partial"
    return resources, status
