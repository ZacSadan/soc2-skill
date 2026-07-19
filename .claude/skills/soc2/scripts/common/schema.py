"""Shared resource schema for SOC2 scanner snapshots.

Every provider scanner emits plain dicts shaped like:
    {"type": "<provider>.<kind>", "id": "<unique-string>",
     "attributes": {...}, "severity": "critical|high|medium|low|info", "tags": [...]}

`id` must be a stable, deterministic string built from a resource's identity
fields (e.g. "sa_key:<email>:<key_id>") so the diff engine can match the same
resource across runs by (type, id) alone.
"""

SCHEMA_VERSION = 1

SEVERITIES = ("critical", "high", "medium", "low", "info")

# type -> watched attribute names, or "*" to watch every attribute for changes.
TYPE_WATCH_FIELDS = {
    "gcp.iam.service_account": "*",
    "gcp.iam.service_account_key": ("age_days", "disabled", "key_type"),
    "gcp.iam.binding": "*",
    "gcp.compute.firewall_rule": "*",
    "gcp.compute.ssh_key_metadata": "*",
    "gcp.apikeys.key": ("restrictions",),
    "gcp.scc.finding": ("state", "severity"),
    "gcp.iam.recommendation": ("state",),
    "gcp.cloudasset.public_binding": "*",
    "gcp.kms.key": ("rotation_period",),
    "gcp.cloudsql.instance": ("require_ssl", "has_public_ip", "authorized_networks"),
    "gcp.secretmanager.secret": ("rotation_period",),
    "gcp.logging.sink": ("destination", "disabled"),
    "gcp.artifactregistry.repository": ("public_bindings",),
    "gcp.pubsub.topic": ("public_bindings",),
    "gcp.gke.cluster": ("private_nodes", "master_authorized_networks_enabled", "legacy_abac_enabled", "basic_auth_enabled", "client_cert_auth_enabled", "workload_identity_enabled", "binary_authorization_enabled"),
    "gcp.dns.zone": ("visibility", "dnssec_state"),
    "gcp.storage.bucket_config": ("uniform_bucket_level_access", "public_access_prevention", "versioning_enabled"),
    "gcp.orgpolicy.constraint": ("enforced", "rules"),
    "bitbucket.repo": ("is_private",),
    "bitbucket.repo_permission": ("permission",),
    "bitbucket.deploy_key": "*",
    "bitbucket.project_access_key": "*",
    "bitbucket.account_ssh_key": "*",
    "bitbucket.webhook": ("url", "events", "active"),
    "bitbucket.branch_restriction": "*",
    "trello.board": ("name", "closed", "visibility"),
    "trello.board_member": ("membership_type",),
    "trello.org_member": ("member_type", "unconfirmed", "deactivated"),
    "aws.iam.user": ("has_console_access", "mfa_enabled"),
    "aws.iam.access_key": ("status", "age_days"),
    "aws.iam.role": ("trust_policy_public",),
    "aws.iam.binding": "*",
    "aws.ec2.security_group": "*",
    "aws.ec2.key_pair": "*",
    "aws.apigateway.key": ("enabled",),
    "aws.securityhub.finding": ("workflow_state", "compliance_status", "severity"),
    "aws.accessanalyzer.finding": ("is_public", "condition"),
    "aws.iam.root_account": ("mfa_enabled", "access_keys_present"),
    "aws.s3.bucket": ("is_public_acl", "is_public_policy", "block_public_access_enabled"),
    "aws.guardduty.finding": ("severity_score",),
    "aws.iam.access_advisor": ("services_used_count",),
    "aws.resourceexplorer.resource_count": ("count",),
    "aws.cloudtrail.trail": ("is_logging", "is_multi_region", "log_file_validation_enabled"),
    "aws.config.recorder": ("recording",),
    "aws.iam.password_policy": ("configured", "minimum_length", "require_symbols", "require_numbers"),
    "aws.kms.key": ("rotation_enabled",),
    "aws.rds.instance": ("publicly_accessible", "storage_encrypted"),
    "aws.ec2.ebs_default_encryption": ("enabled",),
    "aws.ec2.vpc": ("has_flow_log",),
    "gsuite.user": ("suspended", "is_admin", "is_delegated_admin", "is_enrolled_2sv", "is_enforced_2sv"),
    "gsuite.admin_summary": ("super_admin_count", "super_admin_emails"),
    "gsuite.group": ("direct_members_count", "owners", "managers"),
    "gsuite.org_unit": ("parent_org_unit_path", "block_inheritance"),
    "gsuite.mobile_device": ("status", "compromised_status", "encryption_status", "password_status"),
    "gsuite.login_event": "*",
    "gsuite.oauth_grant": "*",
    "confluence.space": ("anonymous_access", "anonymous_operations", "admins", "status"),
    "confluence.space_permission": ("operations", "via"),
    "confluence.other_spaces_summary": ("other_space_count",),
}


def watched_fields(resource_type):
    return TYPE_WATCH_FIELDS.get(resource_type, "*")
