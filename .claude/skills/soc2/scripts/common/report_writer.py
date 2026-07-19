"""Console + Markdown rendering for scan results.

Both renderers consume the same {provider: {"snapshot": dict, "diff": dict}}
structure, so there is no duplicated logic between the two output formats.

GCP and Bitbucket get bespoke chapter-based rendering (see _gcp_chapters/
_bitbucket_chapters/_resolve_chapter_groups below): resources are grouped
into named categories (service accounts, keys, IAM bindings by principal
type, firewall rules, repos, repo permissions, ...) instead of one flat
severity-sorted list, and any category with a real enabled/disabled state
is split into an "(enabled)" group shown before its "(disabled)" group.
Trello keeps the original flat, diff-driven rendering untouched.
"""
import datetime
import re

from .redact import safe_print

# GCE managed instance groups (and similar fleets) commonly spread replicas
# across multiple zones within a region - matching purely on the instance
# name would otherwise split one logical fleet into one group per zone.
_LOCATION_SEGMENT_RE = re.compile(r"/(zones|regions|locations)/[^/]+")

PROVIDER_ORDER = ["gcp", "bitbucket", "trello", "aws", "gsuite", "confluence"]
PROVIDER_LABELS = {
    "gcp": "GCP",
    "bitbucket": "Bitbucket",
    "trello": "Trello",
    "aws": "AWS",
    "gsuite": "Google Workspace",
    "confluence": "Confluence",
}

# Bitbucket's public REST API has no way to list Access Tokens at any scope,
# and gates deploy keys / branch restrictions / project access keys behind
# admin-level OAuth scopes this scanner isn't configured to hold - so these
# specific pages have to be reviewed by hand instead of automated. The actual
# URLs are workspace/project-specific, so they live in
# secrets/soc2.config.private.yaml (bitbucket.manual_review_urls) rather than
# hardcoded here - these are just the fallback if that's not configured.
BITBUCKET_MANUAL_REVIEW_URLS_DEFAULT = [
    "https://id.atlassian.com/manage-profile/security/api-tokens",
]

# OAuth 2.0 Client IDs (APIs & Services > Credentials) have no public API to
# list them at all - a known, long-standing GCP gap (unlike API Keys on the
# same page, which the API Keys API does cover, see scan_api_keys) - so this
# has to be reviewed by hand instead of automated. The actual URL is
# project-specific, so it lives in secrets/soc2.config.private.yaml
# (gcp.manual_review_urls) rather than hardcoded here.
GCP_MANUAL_REVIEW_URLS_DEFAULT = []


def _severity_rank(sev, order):
    try:
        return order.index(sev)
    except ValueError:
        return len(order)


def _sorted_by_severity(resources, order):
    return sorted(resources, key=lambda r: _severity_rank(r.get("severity", "info"), order))


def _fmt_severity_md(sev, disabled=False):
    """Color/weight-codes severity values for markdown output - HTML inline
    styles render in most markdown viewers (GitHub strips the color but
    keeps the bold/underline). Skipped when the resource is disabled: a
    disabled finding is already neutralized, so it shouldn't draw the same
    alarm as an active one. Console output is untouched since a terminal
    can't render either.

    critical: heavy/dark red, bold, underlined - the most severe tier, kept
    visually distinct from high rather than sharing plain red.
    high: red, bold.
    medium: orange, bold."""
    if disabled:
        return sev
    if sev == "critical":
        return f'**<span style="color:darkred; text-decoration:underline">{sev}</span>**'
    if sev == "high":
        return f'**<span style="color:red">{sev}</span>**'
    if sev == "medium":
        return f'**<span style="color:orange">{sev}</span>**'
    return sev


def _fmt_bb_permission_md(perm):
    """Highlights Bitbucket repo permission levels for markdown output:
    "admin" (full control) in red, "write" (push access) in bold."""
    if perm == "admin":
        return f'<span style="color:red">{perm}</span>'
    if perm == "write":
        return f"**{perm}**"
    return perm


PASSWORD_STALE_DAYS = 180  # ~6 months


def _fmt_password_last_used_md(r):
    """Markdown variant of the IAM Users "Password Last Used" column: red
    if the console password hasn't been used in 6+ months. "never" is left
    plain - it usually just means the user has no console access at all
    (see the separate Console Access column), not a stale credential."""
    raw = r["attributes"].get("password_last_used")
    if not raw:
        return "never"
    formatted = raw[:10]
    try:
        last_used = datetime.datetime.fromisoformat(raw)
        age_days = (datetime.datetime.now(datetime.timezone.utc) - last_used).days
    except ValueError:
        return formatted
    if age_days > PASSWORD_STALE_DAYS:
        return f'<span style="color:red">{formatted}</span>'
    return formatted


def _fmt_repo_last_updated_md(r):
    """Red if a Bitbucket repo hasn't been touched in 6+ months (same
    PASSWORD_STALE_DAYS threshold as the AWS IAM Users column - not
    conceptually related, just a reasonable shared "half a year" bar)."""
    raw = r["attributes"].get("updated_on")
    if not raw:
        return "never"
    formatted = raw[:10]
    try:
        updated = datetime.datetime.fromisoformat(raw)
        age_days = (datetime.datetime.now(datetime.timezone.utc) - updated).days
    except ValueError:
        return formatted
    if age_days > PASSWORD_STALE_DAYS:
        return f'<span style="color:red">{formatted}</span>'
    return formatted


TRELLO_STALE_ACTIVITY_DAYS = 90  # ~3 months


def _fmt_trello_last_active_md(raw_iso):
    """Red if the timestamp (org member's last-active, or a board's
    dateLastActivity) is more than 3 months old. Same convention as
    _fmt_password_last_used_md - color only, doesn't change severity."""
    if not raw_iso:
        return "never"
    formatted = raw_iso[:10]
    try:
        last_active = datetime.datetime.fromisoformat(raw_iso.replace("Z", "+00:00"))
        age_days = (datetime.datetime.now(datetime.timezone.utc) - last_active).days
    except ValueError:
        return formatted
    if age_days > TRELLO_STALE_ACTIVITY_DAYS:
        return f'<span style="color:red">{formatted}</span>'
    return formatted


def _fmt_trello_permission_md(perm):
    """Reds "admin" for Trello org/board membership types - same convention
    as _fmt_bb_permission_md."""
    if perm == "admin":
        return f'<span style="color:red">{perm}</span>'
    return perm


def _trello_diff_label(r, board_names_by_id):
    """Resolves a Trello diff-table resource to a human-readable label
    instead of its raw ID (e.g. "Jane Doe" rather than
    "org_member:54cdd77f.../54d333e7..."). Falls back to the raw ID for any
    type/shape this doesn't recognize (e.g. attributes missing on an old
    snapshot predating this field)."""
    a = r.get("attributes") or {}
    t = r.get("type")
    if t == "trello.board":
        return a.get("name") or r["id"]
    if t == "trello.org_member":
        return a.get("full_name") or a.get("username") or r["id"]
    if t == "trello.board_member":
        name = a.get("full_name") or a.get("username") or "(unknown)"
        board = board_names_by_id.get(a.get("board_id"), a.get("board_id"))
        return f"{name} — {board}"
    return r["id"]


# --- GCP chapter formatting helpers -----------------------------------------

def _fmt_date(ts):
    return ts[:10] if ts else "never seen"


def _fmt_has_keys(r):
    a = r["attributes"]
    if a.get("has_keys") is None:
        return "unknown"
    return f"yes ({a.get('key_count')})" if a.get("has_keys") else "no"


def _fmt_public_bindings(r):
    bindings = r["attributes"].get("public_bindings")
    if bindings is None:
        return "unknown (getIamPolicy denied)"
    return ", ".join(bindings) or "none"


def _fmt_authorized_networks(r):
    networks = sorted(r["attributes"].get("authorized_networks") or [], key=lambda n: n.get("name") or "")
    if not networks:
        return "none"
    return ", ".join(f"{n['name']} ({n['value']})" if n.get("name") else n["value"] for n in networks)


def _fmt_authorized_networks_md(r):
    networks = sorted(r["attributes"].get("authorized_networks") or [], key=lambda n: n.get("name") or "")
    if not networks:
        return "none"
    entries = []
    for n in networks:
        value = n["value"]
        value_cell = value if value.endswith("/32") else f'<span style="color:red">{value}</span>'
        entries.append(f"{n['name']} ({value_cell})" if n.get("name") else value_cell)
    return "<br>".join(entries)


def _fmt_usage_per_api(r):
    a = r["attributes"]
    ts = a.get("last_seen_usage_per_api")
    if not ts:
        return "never seen"
    label = a.get("last_seen_usage_per_api_label")
    return f"{ts[:10]} ({label})" if label else ts[:10]


def _fmt_key_auth_per_key(r):
    a = r["attributes"]
    ts = a.get("last_seen_key_auth_per_key")
    if not ts:
        return "never seen"
    key_id = a.get("last_seen_key_auth_per_key_id")
    return f"{ts[:10]} (key ...{key_id[-8:]})" if key_id else ts[:10]


def _fmt_seen_summary(r):
    """Collapses a service account's 4 independent last-seen signals (overall
    usage, usage per API, key-auth traffic, key-auth traffic per key) into
    one field, since showing them as 4 separate table columns made the
    Service Accounts chapter too wide to scan."""
    a = r["attributes"]
    return (
        f"usage: {_fmt_date(a.get('last_seen_usage'))} | "
        f"per-API: {_fmt_usage_per_api(r)} | "
        f"key-auth: {_fmt_date(a.get('last_seen_key_auth'))} | "
        f"per-key: {_fmt_key_auth_per_key(r)}"
    )


def _attr(name, default=""):
    return lambda r: r["attributes"].get(name, default)


# Well-known ports worth naming inline in the Firewall Rules chapter, so
# "80" reads as "80(http)" instead of requiring a lookup.
PORT_LABELS = {
    "20": "ftp-data", "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp",
    "53": "dns", "80": "http", "110": "pop3", "123": "ntp", "143": "imap",
    "443": "https", "445": "smb", "465": "smtps", "587": "smtp-submission",
    "993": "imaps", "995": "pop3s", "1433": "mssql", "1521": "oracle-db",
    "3306": "mysql", "3389": "rdp", "5432": "postgres", "5900": "vnc",
    "6379": "redis", "8080": "http-alt", "8443": "https-alt",
    "9200": "elasticsearch", "27017": "mongodb",
}


def _label_port(port):
    label = PORT_LABELS.get(port)
    return f"{port}({label})" if label else port


def _fmt_allowed(r):
    parts = []
    for a in r["attributes"].get("allowed", []):
        port_list = a.get("ports", [])
        ports = ",".join(_label_port(p) for p in port_list) if port_list else "all"
        parts.append(f"{a.get('IPProtocol')}:{ports}")
    return "; ".join(parts)


def _fmt_source_ranges(r):
    return ", ".join(r["attributes"].get("source_ranges", []))


def _fmt_allowed_md(r):
    """Markdown variant of _fmt_allowed that bolds a fully-open "all:all"
    rule (every protocol, every port) so it stands out from a scoped one
    like "tcp:22(ssh)"."""
    parts = []
    for a in r["attributes"].get("allowed", []):
        port_list = a.get("ports", [])
        ports = ",".join(_label_port(p) for p in port_list) if port_list else "all"
        part = f"{a.get('IPProtocol')}:{ports}"
        parts.append(f"**{part}**" if part == "all:all" else part)
    return "; ".join(parts)


def _fmt_source_ranges_md(r):
    """Markdown variant of _fmt_source_ranges that bolds any range broader
    than a single host (i.e. not /32) - "0.0.0.0/0" or "10.0.0.0/8" stand
    out from a scoped "203.0.113.4/32"."""
    parts = []
    for rng in r["attributes"].get("source_ranges", []):
        parts.append(f"**{rng}**" if not rng.endswith("/32") else rng)
    return ", ".join(parts)


# Fleet/network name prefixes worth calling out inline in the Firewall
# Rules "Name" column - only the matching substring is colored, not the
# whole rule name, so e.g. "corp-fleet-us-east-default" reads with just
# "corp-fleet-us-east" in green. These are this company's own naming
# convention, not a generic default, so the real list lives in
# secrets/soc2.config.private.yaml (gcp.firewall_name_highlights) and is
# pushed into this module-level list once per render call via
# _set_firewall_name_highlights - column-formatter functions like this one
# only ever receive a single resource `r`, not `config`, so a module-level
# list is the pragmatic way to make this configurable without threading
# `config` through every column formatter in the file.
FIREWALL_NAME_HIGHLIGHTS = []


def _set_firewall_name_highlights(patterns):
    FIREWALL_NAME_HIGHLIGHTS[:] = patterns or []


def _fmt_firewall_name_md(r):
    name = r["attributes"].get("name") or ""
    for pattern in FIREWALL_NAME_HIGHLIGHTS:
        if pattern in name:
            name = name.replace(pattern, f'<span style="color:green">{pattern}</span>')
    return name


def _fmt_key_id(r):
    key_id = r["attributes"].get("key_id") or ""
    return key_id[:12] + "..." if len(key_id) > 12 else key_id


def _fmt_created(r):
    return (r["attributes"].get("valid_after") or "")[:10]


def _is_user_member(r):
    return (r["attributes"].get("member") or "").startswith("user:")


def _group_iam_bindings_by_member(resources, order):
    """Collapses one-row-per-(member, role) IAM binding resources into one
    entry per member with every role it holds, so a user with N role
    bindings shows as a single row instead of N near-duplicate rows.
    Returns groups sorted worst-severity-first, each: {"member", "roles":
    [{"role", "severity", "included_permissions"}, ...] sorted by severity,
    "severity": worst severity across the member's roles}.
    """
    members = {}
    for r in resources:
        member = r["attributes"].get("member") or "(unknown)"
        role = r["attributes"].get("role") or "(unknown)"
        severity = r.get("severity", "info")
        included_permissions = r["attributes"].get("included_permissions")
        g = members.setdefault(member, {})
        existing = g.get(role)
        if existing is None or _severity_rank(severity, order) < _severity_rank(existing["severity"], order):
            g[role] = {"severity": severity, "included_permissions": included_permissions}

    groups = []
    for member, roles in members.items():
        role_entries = sorted(
            ({"role": role, **info} for role, info in roles.items()),
            key=lambda x: _severity_rank(x["severity"], order),
        )
        worst_severity = role_entries[0]["severity"] if role_entries else "info"
        groups.append({"member": member, "roles": role_entries, "severity": worst_severity})

    groups.sort(key=lambda g: (_severity_rank(g["severity"], order), g["member"]))
    return groups


def _group_bitbucket_permissions_by_principal(resources, order):
    """Collapses one-row-per-(principal, repo) Bitbucket repo_permission
    resources into one entry per principal with every repo grant it holds,
    so a user/group with access to N repos shows as a single row instead of
    N near-duplicate rows. Returns groups sorted worst-severity-first, each:
    {"principal", "grants": [{"workspace", "repo_slug", "permission",
    "severity"}, ...] sorted lexicographically by workspace/repo so a long
    grant list reads as a scannable, alphabetized list, "severity": worst
    severity across the principal's grants}.
    """
    principals = {}
    for r in resources:
        a = r["attributes"]
        principal = a.get("principal") or "(unknown)"
        principals.setdefault(principal, []).append({
            "workspace": a.get("workspace"),
            "repo_slug": a.get("repo_slug"),
            "permission": a.get("permission"),
            "severity": r.get("severity", "info"),
        })

    groups = []
    for principal, grants in principals.items():
        grants = sorted(grants, key=lambda x: (x["workspace"] or "", x["repo_slug"] or ""))
        worst_severity = min(
            (g["severity"] for g in grants), key=lambda s: _severity_rank(s, order), default="info"
        )
        groups.append({"principal": principal, "grants": grants, "severity": worst_severity})

    groups.sort(key=lambda g: (_severity_rank(g["severity"], order), g["principal"]))
    return groups


def _group_aws_bindings_by_principal(resources, order):
    """Collapses one-row-per-(principal, policy) AWS IAM binding resources
    into one entry per (principal_type, principal) with every policy it
    holds, so a user/role/group with N attached policies shows as a single
    row instead of N near-duplicate rows."""
    principals = {}
    for r in resources:
        a = r["attributes"]
        key = (a.get("principal_type"), a.get("principal") or "(unknown)")
        principals.setdefault(key, []).append({
            "policy_name": a.get("policy_name"),
            "is_inline": "inline" in r.get("tags", []),
            "severity": r.get("severity", "info"),
        })

    groups = []
    for (principal_type, principal), policies in principals.items():
        policies = sorted(policies, key=lambda x: _severity_rank(x["severity"], order))
        worst_severity = policies[0]["severity"] if policies else "info"
        groups.append({
            "principal_type": principal_type, "principal": principal,
            "policies": policies, "severity": worst_severity,
        })

    groups.sort(key=lambda g: (_severity_rank(g["severity"], order), g["principal"]))
    return groups


def _group_trello_board_members_by_member(resources, board_info_by_id, order):
    """Collapses one-row-per-(member, board) Trello board_member resources
    into one entry per member with every board they can access and their
    permission level on each, so a member on N boards shows as a single row
    instead of N near-duplicate rows. Mirrors
    _group_bitbucket_permissions_by_principal - same shape, different
    provider. board_info_by_id resolves the board_id each resource carries
    to {"name", "closed"} (board_member resources don't carry the board's
    name or closed-status themselves).

    Grouped by member_id, NOT by display name - Trello's full_name is a
    free-text field with no uniqueness constraint, and this workspace has
    multiple distinct accounts sharing the same display name (e.g. several
    "Jane Doe" accounts with different usernames). Grouping by name alone
    would silently merge unrelated accounts' board access into one row.
    """
    members = {}
    for r in resources:
        a = r["attributes"]
        member_id = a.get("member_id") or "(unknown)"
        display_name = a.get("full_name") or a.get("username") or member_id
        board_info = board_info_by_id.get(a.get("board_id"), {})
        entry = members.setdefault(member_id, {
            "display_name": display_name, "username": a.get("username"),
            "last_active": a.get("last_active"), "boards": [],
        })
        entry["boards"].append({
            "board_id": a.get("board_id"),
            "board_name": board_info.get("name", a.get("board_id")),
            "closed": bool(board_info.get("closed")),
            "membership_type": a.get("membership_type"),
            "severity": r.get("severity", "info"),
        })

    groups = []
    for member_id, entry in members.items():
        boards = sorted(entry["boards"], key=lambda x: (x["board_name"] or ""))
        worst_severity = min(
            (b["severity"] for b in boards), key=lambda s: _severity_rank(s, order), default="info"
        )
        display_name, username = entry["display_name"], entry["username"]
        # Skip the bracket when the display name already IS the username
        # (members with no full_name set) - "jdoe (jdoe)" would be noise.
        label = f"{display_name} ({username})" if username and username != display_name else display_name
        # Case/punctuation-normalized name to sort by, so accounts that
        # share a name but differ in case or formatting (e.g. "Jane Doe"
        # vs "jane.doe" - two distinct Trello accounts) cluster together
        # instead of being split apart by a case-sensitive alphabetical
        # sort (which places every "jane.doe"-style lowercase name after
        # ALL capitalized names, not next to its near-namesakes).
        sort_name = re.sub(r"[.\s_]", "", display_name).lower()
        groups.append({
            "member": label, "last_active": entry["last_active"],
            "boards": boards, "severity": worst_severity, "_sort_name": sort_name,
        })

    groups.sort(key=lambda g: (_severity_rank(g["severity"], order), g["_sort_name"], g["member"]))
    for g in groups:
        del g["_sort_name"]
    return groups


MOBILE_DEVICE_STALE_SYNC_DAYS = 30  # ~1 month


def _group_gsuite_mobile_devices_by_owner(resources, order):
    """Collapses one-row-per-device gsuite.mobile_device resources into one
    entry per owner with every device they have registered, mirroring the
    Trello board-member / Bitbucket SSH-key grouping pattern elsewhere in
    this file."""
    owners = {}
    for r in resources:
        a = r["attributes"]
        owner = a.get("owner_email") or "(unknown)"
        owners.setdefault(owner, []).append({
            "model": a.get("model"), "os": a.get("os"), "status": a.get("status"),
            "compromised_status": a.get("compromised_status"),
            "encryption_status": a.get("encryption_status"),
            "password_status": a.get("password_status"),
            "last_sync": a.get("last_sync"),
            "last_sync_age_days": a.get("last_sync_age_days"),
            "severity": r.get("severity", "info"),
        })

    groups = []
    for owner, devices in owners.items():
        devices = sorted(devices, key=lambda d: _severity_rank(d["severity"], order))
        worst_severity = devices[0]["severity"] if devices else "info"
        groups.append({"owner": owner, "devices": devices, "severity": worst_severity})

    groups.sort(key=lambda g: (_severity_rank(g["severity"], order), g["owner"]))
    return groups


def _group_bitbucket_ssh_keys_by_account(resources, order):
    """Collapses one-row-per-key Bitbucket account_ssh_key resources into
    one entry per (workspace, account) with every key it has registered."""
    accounts = {}
    for r in resources:
        a = r["attributes"]
        key = (a.get("workspace"), a.get("account") or "(unknown)")
        accounts.setdefault(key, []).append({
            "label": a.get("label"), "comment": a.get("comment"), "last_used": a.get("last_used"),
            "severity": r.get("severity", "info"),
        })

    groups = []
    for (workspace, account), keys in accounts.items():
        keys = sorted(keys, key=lambda k: _severity_rank(k["severity"], order))
        worst_severity = keys[0]["severity"] if keys else "info"
        groups.append({"workspace": workspace, "account": account, "keys": keys, "severity": worst_severity})

    groups.sort(key=lambda g: (_severity_rank(g["severity"], order), g["account"]))
    return groups


def _group_ssh_keys_by_username(resources, order):
    """Collapses one-row-per-key GCE ssh_key_metadata resources into one
    entry per username with every key (project- and instance-scoped)
    registered under it."""
    users = {}
    for r in resources:
        a = r["attributes"]
        username = a.get("username") or "(unknown)"
        users.setdefault(username, []).append({
            "scope": a.get("scope"), "scope_id": a.get("scope_id"),
            "algorithm": a.get("algorithm"), "fingerprint": a.get("fingerprint"),
            "severity": r.get("severity", "info"),
        })

    groups = []
    for username, keys in users.items():
        keys = sorted(keys, key=lambda k: _severity_rank(k["severity"], order))
        worst_severity = keys[0]["severity"] if keys else "info"
        groups.append({"username": username, "keys": keys, "severity": worst_severity})

    groups.sort(key=lambda g: (_severity_rank(g["severity"], order), g["username"]))
    return groups


def _scc_resource_stem(resource_name):
    """Candidate grouping key for an SCC finding's resource path, with the
    wildcard already embedded - the caller just compares this against the
    original resource_name to know whether anything was stripped.

    The path's zone/region/location segment (if any) is normalized to a
    wildcard first, since a fleet's replicas commonly spread across multiple
    zones within a region - matching on instance name alone would otherwise
    split one logical fleet into a separate group per zone.

    Then two naming patterns are recognized on the final path segment:
    - Dot-separated (e.g. GCS bucket names using a reverse-DNS-style name
      with a per-project numeric prefix) vary at the START:
      "//storage.googleapis.com/1000971.reports.example.com" ->
      "//storage.googleapis.com/*.reports.example.com".
    - Hyphen-separated (e.g. GCE instances / MIG replicas) vary at the END:
      ".../zones/us-central1-b/instances/worker-fleet-mig-0qls" ->
      ".../zones/*/instances/worker-fleet-mig-*".
    Dots take priority when a segment has both (domain-like names read
    right-to-left; the meaningful part is the suffix, not any hyphenated
    word within it). Returns the resource_name unchanged if neither pattern
    applies (no "/", or the last path segment has no "." or "-").
    """
    if not resource_name or "/" not in resource_name:
        return resource_name
    prefix, _, last = resource_name.rpartition("/")
    prefix = _LOCATION_SEGMENT_RE.sub(lambda m: f"/{m.group(1)}/*", prefix, count=1)
    if "." in last:
        _lead, _, rest = last.partition(".")
        if rest:
            return f"{prefix}/*.{rest}"
    elif "-" in last:
        stem, _, _suffix = last.rpartition("-")
        if stem:
            return f"{prefix}/{stem}-*"
    return resource_name


SCC_SERVICE_LABELS = {
    "compute.googleapis.com": "Compute",
    "storage.googleapis.com": "Storage",
    "iam.googleapis.com": "IAM",
    "container.googleapis.com": "Kubernetes Engine",
    "cloudsql.googleapis.com": "Cloud SQL",
    "run.googleapis.com": "Cloud Run",
    "cloudresourcemanager.googleapis.com": "Resource Manager",
}

SCC_KIND_LABELS = {
    "instances": "Instances",
    "firewalls": "Firewall Rules",
    "subnetworks": "Subnetworks",
    "networks": "Networks",
    "backendServices": "Backend Services",
    "sslPolicies": "SSL Policies",
    "keys": "Keys",
    "clusters": "Clusters",
    "services": "Services",
    "projects": "Projects",
}


def _scc_resource_section(resource_name):
    """Buckets an SCC finding's resource into a report section by GCP
    service + resource kind - e.g. "Compute - Instances", "Compute -
    Firewall Rules", "Storage - Buckets", "IAM - Keys". Unknown services/
    kinds fall back to their raw name rather than disappearing, so a
    resource type not in the lookup tables still gets a sensible section.
    """
    if not resource_name or not resource_name.startswith("//"):
        return "Other"
    parts = resource_name[2:].split("/")
    service = parts[0]
    service_label = SCC_SERVICE_LABELS.get(service, service)
    if len(parts) < 3:
        kind_label = "Buckets" if service == "storage.googleapis.com" else "Resources"
    else:
        kind_label = SCC_KIND_LABELS.get(parts[-2], parts[-2])
    return f"{service_label} - {kind_label}"


def _scc_short_name(full_name):
    return (full_name or "").rsplit("/", 1)[-1]


def _group_scc_findings(findings, order):
    """Groups SCC findings by resource, collapsing resources that share a
    stem (see _scc_resource_stem) under a wildcard - but only when 2+
    distinct resource names actually share that stem, so a genuinely unique
    resource whose name happens to contain a hyphen isn't turned into a
    spurious single-member "group". Returns groups sorted worst-severity-
    first, each: {"resource": full resource path (wildcarded if grouped) -
    for display *inside* the group, "short_name": just the last path
    segment - for display *outside*/as the group's visible label,
    "section": GCP service/resource-kind section title, "instance_count":
    int, "severity": worst severity in the group, "categories":
    [{"category", "count", "severity"}, ...] sorted by severity}.
    """
    stem_members = {}
    for f in findings:
        stem = _scc_resource_stem(f["attributes"].get("resource_name"))
        stem_members.setdefault(stem, set()).add(f["attributes"].get("resource_name"))

    groups = {}
    for f in findings:
        resource_name = f["attributes"].get("resource_name")
        stem = _scc_resource_stem(resource_name)
        is_grouped = stem != resource_name and len(stem_members.get(stem, ())) > 1
        full_name = stem if is_grouped else (resource_name or "(unknown resource)")

        g = groups.setdefault(full_name, {"resources": set(), "categories": {}, "section": _scc_resource_section(resource_name)})
        g["resources"].add(resource_name)
        finding_category = f["attributes"].get("category") or "UNKNOWN"
        severity = f.get("severity", "info")
        cat_entry = g["categories"].setdefault(finding_category, {"count": 0, "severity": severity})
        cat_entry["count"] += 1
        if _severity_rank(severity, order) < _severity_rank(cat_entry["severity"], order):
            cat_entry["severity"] = severity

    result = []
    for full_name, g in groups.items():
        categories = sorted(
            ({"category": cat, **info} for cat, info in g["categories"].items()),
            key=lambda c: _severity_rank(c["severity"], order),
        )
        worst_severity = categories[0]["severity"] if categories else "info"
        result.append({
            "resource": full_name,
            "short_name": _scc_short_name(full_name),
            "section": g["section"],
            "instance_count": len(g["resources"]),
            "severity": worst_severity,
            "categories": categories,
            "_resources": g["resources"],
        })
    result.sort(key=lambda g: (_severity_rank(g["severity"], order), -g["instance_count"]))
    return result


def _merge_related_scc_groups(groups, order):
    """Second pass over already-grouped SCC resources: merges groups
    further when their short names share a long common hyphen-prefix that a
    single trailing-segment strip (_scc_resource_stem) wouldn't reach - e.g.
    "web-fleet-mig-regional-ae-preemptible-*",
    "...-regional-eu-preemptible-*", and "...-regional-sa-*" all share
    "web-fleet-mig-regional", spread across 3 regions with an extra
    differentiator segment ("ae"/"eu"/"sa", "preemptible") between the fleet
    name and the random per-instance suffix.

    Two groups are linked when they have the same path prefix (everything
    before the last segment) and their short names' hyphen-segments share a
    prefix of at least 2 segments, with at most 2 leftover (unmatched)
    segments on *each* side. The leftover cap is deliberately an absolute
    count, not a proportion of the name's length - a proportional threshold
    (e.g. "50% of the shorter name") still merges cases like
    "batch-worker-fast-app-frontend-us-central-mig-*" with
    "batch-worker-fast-app-backend-store-us-central-mig-*": they share
    "batch-worker-fast-app" (4 of 8 segments = 50%), but "frontend" vs
    "backend-store" are different resource roles, not fleet replicas -
    genuine per-instance differentiators (a region code, "preemptible", a
    random suffix) are short in absolute terms regardless of how long the
    rest of the name is.
    """
    def strip_wildcard(name):
        return name[:-2] if name.endswith("-*") else name

    def path_prefix(full_name):
        return full_name.rsplit("/", 1)[0] if "/" in full_name else ""

    n = len(groups)
    segs = [strip_wildcard(g["short_name"]).split("-") for g in groups]
    prefixes = [path_prefix(g["resource"]) for g in groups]

    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    for i in range(n):
        for j in range(i + 1, n):
            if prefixes[i] != prefixes[j]:
                continue
            a, b = segs[i], segs[j]
            shared = 0
            for x, y in zip(a, b):
                if x != y:
                    break
                shared += 1
            if shared >= 2 and (len(a) - shared) <= 2 and (len(b) - shared) <= 2:
                union(i, j)

    components = {}
    for idx in range(n):
        components.setdefault(find(idx), []).append(idx)

    merged = []
    for idxs in components.values():
        if len(idxs) == 1:
            merged.append(groups[idxs[0]])
            continue

        member_groups = [groups[i] for i in idxs]
        common = []
        for seg_tuple in zip(*(segs[i] for i in idxs)):
            if len(set(seg_tuple)) != 1:
                break
            common.append(seg_tuple[0])

        prefix = prefixes[idxs[0]]
        short_name = (("-".join(common) + "-*") if common else "*")
        full_name = f"{prefix}/{short_name}" if prefix else short_name

        all_resources = set()
        merged_categories = {}
        for g in member_groups:
            all_resources.update(g["_resources"])
            for c in g["categories"]:
                entry = merged_categories.setdefault(c["category"], {"count": 0, "severity": c["severity"]})
                entry["count"] += c["count"]
                if _severity_rank(c["severity"], order) < _severity_rank(entry["severity"], order):
                    entry["severity"] = c["severity"]

        categories = sorted(
            ({"category": k, **v} for k, v in merged_categories.items()),
            key=lambda c: _severity_rank(c["severity"], order),
        )
        worst_severity = categories[0]["severity"] if categories else "info"
        merged.append({
            "resource": full_name,
            "short_name": short_name,
            "section": member_groups[0]["section"],
            "instance_count": len(all_resources),
            "severity": worst_severity,
            "categories": categories,
            "_resources": all_resources,
        })

    merged.sort(key=lambda g: (_severity_rank(g["severity"], order), -g["instance_count"]))
    return merged


def _merge_groups_by_category_profile(groups, order):
    """Third pass over already fleet-merged SCC groups: combines groups that
    share the exact same set of category names (regardless of resource
    name) into a single entry, since unrelated fleets that happen to suffer
    from the same combination of findings (e.g. every instance in the
    project has PUBLIC_IP_ADDRESS + FULL_API_ACCESS) are more useful shown
    as one table with counts summed than as N near-identical tables.

    Each merged entry loses its single "resource"/"short_name" (there isn't
    one anymore) in favor of "resource_list": the sorted full resource path
    of every contributing group, for display as a bullet list under the
    combined table.
    """
    buckets = {}
    for g in groups:
        profile = frozenset(c["category"] for c in g["categories"])
        buckets.setdefault((g["section"], profile), []).append(g)

    merged = []
    for (_section, _profile), member_groups in buckets.items():
        if len(member_groups) == 1:
            g = member_groups[0]
            merged.append({**g, "resource_list": [g["resource"]]})
            continue

        merged_categories = {}
        all_resources = set()
        for g in member_groups:
            all_resources.update(g["_resources"])
            for c in g["categories"]:
                entry = merged_categories.setdefault(c["category"], {"count": 0, "severity": c["severity"]})
                entry["count"] += c["count"]
                if _severity_rank(c["severity"], order) < _severity_rank(entry["severity"], order):
                    entry["severity"] = c["severity"]

        categories = sorted(
            ({"category": k, **v} for k, v in merged_categories.items()),
            key=lambda c: _severity_rank(c["severity"], order),
        )
        worst_severity = categories[0]["severity"] if categories else "info"
        merged.append({
            "section": member_groups[0]["section"],
            "instance_count": len(all_resources),
            "severity": worst_severity,
            "categories": categories,
            "_resources": all_resources,
            "resource_list": sorted(g["resource"] for g in member_groups),
        })

    merged.sort(key=lambda g: (_severity_rank(g["severity"], order), -g["instance_count"]))
    return merged


def _group_scc_findings_by_section(findings, order):
    """Returns [(section_title, [group, ...]), ...] sorted by the worst
    severity present in the section, then by total finding count desc."""
    groups = _merge_related_scc_groups(_group_scc_findings(findings, order), order)
    groups = _merge_groups_by_category_profile(groups, order)
    sections = {}
    for g in groups:
        sections.setdefault(g["section"], []).append(g)

    def section_sort_key(item):
        _title, section_groups = item
        worst = min(_severity_rank(g["severity"], order) for g in section_groups)
        total_findings = sum(sum(c["count"] for c in g["categories"]) for g in section_groups)
        return (worst, -total_findings)

    return sorted(sections.items(), key=section_sort_key)


GCP_KNOWN_TYPES = {
    "gcp.iam.service_account",
    "gcp.iam.service_account_key",
    "gcp.iam.binding",
    "gcp.compute.firewall_rule",
    "gcp.compute.ssh_key_metadata",
    "gcp.apikeys.key",
    "gcp.scc.finding",
    "gcp.iam.recommendation",
    "gcp.cloudasset.public_binding",
    "gcp.kms.key",
    "gcp.cloudsql.instance",
    "gcp.secretmanager.secret",
    "gcp.logging.sink",
    "gcp.artifactregistry.repository",
    "gcp.pubsub.topic",
    "gcp.gke.cluster",
    "gcp.dns.zone",
    "gcp.storage.bucket_config",
    "gcp.orgpolicy.constraint",
}


def _build_collapsible_groups_from_config(group_defs):
    """Converts secrets/soc2.config.private.yaml-style group definitions
    (list of {"label", "prefix"} or {"label", "substrings": [...]}) into the
    (label, predicate) tuples _render_collapsible_groups_markdown expects.
    Returns [] if none configured - the chapter then just renders as one
    flat table, same as before this was made configurable."""
    groups = []
    for g in group_defs or []:
        label = g.get("label", "")
        if "prefix" in g:
            prefix = g["prefix"]
            predicate = lambda r, p=prefix: (r["attributes"].get("name") or "").startswith(p)
        else:
            substrings = g.get("substrings", [])
            predicate = lambda r, subs=tuple(substrings): any(s in (r["attributes"].get("name") or "") for s in subs)
        groups.append((label, predicate))
    return groups


def _gcp_chapters(resources, config=None):
    """Buckets GCP resources into named report chapters. Each chapter is
    always shown (even if empty) except the "Other Findings" catch-all,
    which only appears if a resource type isn't in GCP_KNOWN_TYPES (a safety
    net for future scanner additions, not a real category)."""
    gcp_cfg = (config or {}).get("gcp", {})
    _set_firewall_name_highlights(gcp_cfg.get("firewall_name_highlights", []))
    bucket_collapsible_groups = _build_collapsible_groups_from_config(gcp_cfg.get("storage_bucket_collapsible_groups"))

    by_type = {t: [] for t in GCP_KNOWN_TYPES}
    other = []
    for r in resources:
        if r["type"] in by_type:
            by_type[r["type"]].append(r)
        else:
            other.append(r)

    bindings = by_type["gcp.iam.binding"]
    binding_users = [r for r in bindings if _is_user_member(r)]
    # serviceAccount: bindings are shown nested under Service Accounts (via
    # roles_by_email below), so this chapter only needs to cover group:
    # bindings - the one member kind not shown anywhere else.
    binding_groups = [r for r in bindings if (r["attributes"].get("member") or "").startswith("group:")]

    keys_by_email = {}
    for k in by_type["gcp.iam.service_account_key"]:
        keys_by_email.setdefault(k["attributes"].get("service_account"), []).append(k)

    roles_by_email = {}
    for b in bindings:
        member = b["attributes"].get("member") or ""
        if member.startswith("serviceAccount:"):
            email = member.split(":", 1)[1]
            roles_by_email.setdefault(email, []).append({
                "role": b["attributes"].get("role"),
                "severity": b.get("severity", "info"),
                "included_permissions": b["attributes"].get("included_permissions"),
            })

    chapters = [
        {
            "title": "Service Accounts",
            "resources": by_type["gcp.iam.service_account"],
            "split_disabled": True,
            "custom_render": "service_accounts",
            "keys_by_email": keys_by_email,
            "roles_by_email": roles_by_email,
            "columns": [
                ("Email", _attr("email")),
                ("Has Key(s)", _fmt_has_keys),
                ("Last Seen", _fmt_seen_summary),
            ],
        },
        {
            "title": "IAM Bindings - Users",
            "resources": binding_users,
            "split_disabled": False,
            "custom_render": "iam_users",
            "columns": [("User", _attr("member")), ("Role", _attr("role"))],
        },
        {
            "title": "IAM Bindings - Groups",
            "resources": binding_groups,
            "split_disabled": False,
            "columns": [("Principal", _attr("member")), ("Role", _attr("role"))],
        },
        {
            "title": "Firewall Rules",
            "resources": by_type["gcp.compute.firewall_rule"],
            "split_disabled": True,
            "gray_disabled": True,
            "columns": [
                ("Name", _attr("name")),
                ("Direction", _attr("direction")),
                ("Source Ranges", _fmt_source_ranges),
                ("Allowed", _fmt_allowed),
                ("Network", _attr("network")),
            ],
            "columns_md": [
                ("Name", _fmt_firewall_name_md),
                ("Direction", _attr("direction")),
                ("Source Ranges", _fmt_source_ranges_md),
                ("Allowed", _fmt_allowed_md),
                ("Network", _attr("network")),
            ],
        },
        {
            "title": "SSH Keys",
            "resources": by_type["gcp.compute.ssh_key_metadata"],
            "split_disabled": False,
            "custom_render": "ssh_keys",
            "columns": [
                ("Scope", _attr("scope")),
                ("Scope ID", _attr("scope_id")),
                ("Username", _attr("username")),
                ("Algorithm", _attr("algorithm")),
                ("Fingerprint", _attr("fingerprint")),
            ],
        },
        {
            "title": "Security Command Center Findings",
            "resources": by_type["gcp.scc.finding"],
            "split_disabled": False,
            "custom_render": "scc",
            "columns": [("Category", _attr("category")), ("State", _attr("state")), ("Resource", _attr("resource_name"))],
        },
        {
            "title": "IAM Recommendations",
            "resources": by_type["gcp.iam.recommendation"],
            "split_disabled": False,
            "columns": [("Description", _attr("description")), ("State", _attr("state")), ("Priority", _attr("priority"))],
        },
        {
            "title": "API Keys",
            "resources": by_type["gcp.apikeys.key"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("display_name")),
                ("Created", lambda r: (r["attributes"].get("create_time") or "")[:10]),
                ("Restrictions", lambda r: ", ".join(r["attributes"].get("restrictions", [])) or "none"),
            ],
        },
        {
            "title": "Cloud Asset - Public IAM Bindings",
            "resources": by_type["gcp.cloudasset.public_binding"],
            "split_disabled": False,
            "columns": [
                ("Resource", _attr("resource")),
                ("Asset Type", _attr("asset_type")),
                ("Role", _attr("role")),
                ("Member", _attr("member")),
            ],
        },
        {
            "title": "Cloud KMS Keys",
            "resources": by_type["gcp.kms.key"],
            "split_disabled": False,
            "columns": [
                ("Name", lambda r: r["attributes"].get("name", "").rsplit("/", 1)[-1]),
                ("Location", _attr("location")),
                ("Key Ring", _attr("key_ring")),
                ("Rotation Period", lambda r: r["attributes"].get("rotation_period") or "none"),
            ],
        },
        {
            "title": "Cloud SQL Instances",
            "resources": by_type["gcp.cloudsql.instance"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("name")),
                ("Version", _attr("database_version")),
                ("Public IP", _attr("has_public_ip")),
                ("Require SSL", _attr("require_ssl")),
                ("Authorized Networks", _fmt_authorized_networks),
            ],
            "columns_md": [
                ("Name", _attr("name")),
                ("Version", _attr("database_version")),
                ("Public IP", _attr("has_public_ip")),
                ("Require SSL", _attr("require_ssl")),
                ("Authorized Networks", _fmt_authorized_networks_md),
            ],
        },
        {
            "title": "Secret Manager Secrets",
            "resources": by_type["gcp.secretmanager.secret"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("name")),
                ("Created", lambda r: (r["attributes"].get("create_time") or "")[:10]),
                ("Rotation Period", lambda r: r["attributes"].get("rotation_period") or "none"),
            ],
        },
        {
            "title": "Cloud Logging Sinks",
            "resources": by_type["gcp.logging.sink"],
            "split_disabled": False,
            "columns": [
                ("Name", lambda r: (r["attributes"].get("name") or "").rsplit("/", 1)[-1]),
                ("Destination", _attr("destination")),
                ("Disabled", _attr("disabled")),
            ],
        },
        {
            "title": "Artifact Registry Repositories",
            "resources": by_type["gcp.artifactregistry.repository"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("name")),
                ("Location", _attr("location")),
                ("Format", _attr("format")),
                ("Public Bindings", _fmt_public_bindings),
            ],
        },
        {
            "title": "Pub/Sub Topics",
            "resources": by_type["gcp.pubsub.topic"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("name")),
                ("Public Bindings", _fmt_public_bindings),
            ],
        },
        {
            "title": "GKE Clusters",
            "resources": by_type["gcp.gke.cluster"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("name")),
                ("Location", _attr("location")),
                ("Private Nodes", _attr("private_nodes")),
                ("Master Auth Networks", _attr("master_authorized_networks_enabled")),
                ("Legacy ABAC", _attr("legacy_abac_enabled")),
                ("Basic/Cert Auth", lambda r: r["attributes"].get("basic_auth_enabled") or r["attributes"].get("client_cert_auth_enabled")),
                ("Workload Identity", _attr("workload_identity_enabled")),
                ("Binary Authorization", _attr("binary_authorization_enabled")),
            ],
        },
        {
            "title": "Cloud DNS Zones",
            "resources": by_type["gcp.dns.zone"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("name")),
                ("DNS Name", _attr("dns_name")),
                ("Visibility", _attr("visibility")),
                ("DNSSEC", _attr("dnssec_state")),
            ],
        },
        {
            "title": "Storage Bucket Config",
            "resources": by_type["gcp.storage.bucket_config"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("name")),
                ("Location", _attr("location")),
                ("Uniform Access", _attr("uniform_bucket_level_access")),
                ("Public Access Prevention", _attr("public_access_prevention")),
                ("Versioning", _attr("versioning_enabled")),
            ],
            "collapsible_groups": bucket_collapsible_groups,
        },
        {
            "title": "Org Policy Constraints",
            "resources": by_type["gcp.orgpolicy.constraint"],
            "split_disabled": False,
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("constraint") or ""),
            "columns": [
                ("Constraint", _attr("constraint")),
                ("Enforced", _attr("enforced")),
            ],
            "columns_md": [
                ("Constraint", _attr("constraint")),
                ("Enforced", lambda r: _fmt_bool_red_if_md(r["attributes"].get("enforced"), red_if=False)),
            ],
        },
    ]
    if other:
        chapters.append({
            "title": "Other Findings",
            "resources": other,
            "split_disabled": False,
            "columns": [("Type", lambda r: r["type"]), ("ID", lambda r: r["id"]), ("Tags", lambda r: ", ".join(r.get("tags", [])))],
        })
    return chapters


BITBUCKET_KNOWN_TYPES = {
    "bitbucket.repo",
    "bitbucket.repo_permission",
    "bitbucket.deploy_key",
    "bitbucket.project_access_key",
    "bitbucket.account_ssh_key",
    "bitbucket.webhook",
    "bitbucket.branch_restriction",
}


def _bitbucket_chapters(resources):
    """Buckets Bitbucket resources into named report chapters, the same
    dedicated-chapter treatment GCP gets (see _gcp_chapters), instead of one
    flat severity-sorted list."""
    by_type = {t: [] for t in BITBUCKET_KNOWN_TYPES}
    other = []
    for r in resources:
        if r["type"] in by_type:
            by_type[r["type"]].append(r)
        else:
            other.append(r)

    chapters = [
        {
            "title": "Repos",
            "resources": by_type["bitbucket.repo"],
            "split_disabled": False,
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("repo_slug") or ""),
            "columns": [
                ("Workspace", _attr("workspace")),
                ("Repo", _attr("repo_slug")),
                ("Private", lambda r: "yes" if r["attributes"].get("is_private") else "no"),
                ("Last Updated", lambda r: (r["attributes"].get("updated_on") or "never")[:10]),
            ],
            "columns_md": [
                ("Workspace", _attr("workspace")),
                ("Repo", _attr("repo_slug")),
                ("Private", lambda r: "yes" if r["attributes"].get("is_private") else "no"),
                ("Last Updated", _fmt_repo_last_updated_md),
            ],
        },
        {
            "title": "Repo Permissions",
            "resources": by_type["bitbucket.repo_permission"],
            "split_disabled": False,
            "custom_render": "bitbucket_principals",
            "columns": [
                ("Workspace", _attr("workspace")),
                ("Repo", _attr("repo_slug")),
                ("Principal", _attr("principal")),
                ("Permission", _attr("permission")),
            ],
        },
        {
            "title": "Deploy Keys",
            "resources": by_type["bitbucket.deploy_key"],
            "split_disabled": False,
            "columns": [
                ("Workspace", _attr("workspace")),
                ("Repo", _attr("repo_slug")),
                ("Label", _attr("label")),
                ("Comment", _attr("comment")),
            ],
        },
        {
            "title": "Project Access Keys",
            "resources": by_type["bitbucket.project_access_key"],
            "split_disabled": False,
            "columns": [
                ("Workspace", _attr("workspace")),
                ("Project", _attr("project_key")),
                ("Label", _attr("label")),
                ("Comment", _attr("comment")),
            ],
        },
        {
            "title": "Account SSH Keys",
            "resources": by_type["bitbucket.account_ssh_key"],
            "split_disabled": False,
            "custom_render": "bitbucket_ssh_keys",
            "columns": [
                ("Workspace", _attr("workspace")),
                ("Account", _attr("account")),
                ("Label", _attr("label")),
                ("Comment", _attr("comment")),
            ],
        },
        {
            "title": "Webhooks",
            "resources": by_type["bitbucket.webhook"],
            "split_disabled": True,
            "disabled_predicate": lambda r: not r["attributes"].get("active", True),
            "columns": [
                ("Workspace", _attr("workspace")),
                ("Repo", _attr("repo_slug")),
                ("URL", _attr("url")),
                ("Events", lambda r: ", ".join(r["attributes"].get("events", []))),
            ],
        },
        {
            "title": "Branch Restrictions",
            "resources": by_type["bitbucket.branch_restriction"],
            "split_disabled": False,
            "columns": [
                ("Workspace", _attr("workspace")),
                ("Repo", _attr("repo_slug")),
                ("Kind", _attr("kind")),
                ("Pattern", _attr("pattern")),
            ],
        },
    ]
    if other:
        chapters.append({
            "title": "Other Findings",
            "resources": other,
            "split_disabled": False,
            "columns": [("Type", lambda r: r["type"]), ("ID", lambda r: r["id"]), ("Tags", lambda r: ", ".join(r.get("tags", [])))],
        })
    return chapters


AWS_KNOWN_TYPES = {
    "aws.iam.user",
    "aws.iam.access_key",
    "aws.iam.role",
    "aws.iam.binding",
    "aws.iam.root_account",
    "aws.iam.access_advisor",
    "aws.ec2.security_group",
    "aws.ec2.key_pair",
    "aws.s3.bucket",
    "aws.apigateway.key",
    "aws.securityhub.finding",
    "aws.guardduty.finding",
    "aws.accessanalyzer.finding",
    "aws.resourceexplorer.resource_count",
    "aws.cloudtrail.trail",
    "aws.config.recorder",
    "aws.iam.password_policy",
    "aws.kms.key",
    "aws.rds.instance",
    "aws.ec2.ebs_default_encryption",
    "aws.ec2.vpc",
}


def _aws_chapters(resources):
    """Buckets AWS resources into named report chapters, the same
    dedicated-chapter treatment GCP/Bitbucket get, instead of one flat
    severity-sorted list."""
    by_type = {t: [] for t in AWS_KNOWN_TYPES}
    other = []
    for r in resources:
        if r["type"] in by_type:
            by_type[r["type"]].append(r)
        else:
            other.append(r)

    chapters = [
        {
            "title": "Root Account",
            "resources": by_type["aws.iam.root_account"],
            "split_disabled": False,
            "columns": [
                ("MFA Enabled", lambda r: "yes" if r["attributes"].get("mfa_enabled") else "no"),
                ("Access Keys Present", lambda r: "yes" if r["attributes"].get("access_keys_present") else "no"),
                ("Signing Certs Present", lambda r: "yes" if r["attributes"].get("signing_certificates_present") else "no"),
            ],
        },
        {
            "title": "IAM Users",
            "resources": by_type["aws.iam.user"],
            "split_disabled": False,
            "columns": [
                ("User Name", _attr("user_name")),
                ("Console Access", lambda r: "yes" if r["attributes"].get("has_console_access") else "no"),
                ("MFA Enabled", lambda r: "yes" if r["attributes"].get("mfa_enabled") else "no"),
                ("Password Last Used", lambda r: (r["attributes"].get("password_last_used") or "never")[:10]),
            ],
            "columns_md": [
                ("User Name", _attr("user_name")),
                ("Console Access", lambda r: "yes" if r["attributes"].get("has_console_access") else "no"),
                ("MFA Enabled", lambda r: "yes" if r["attributes"].get("mfa_enabled") else "no"),
                ("Password Last Used", _fmt_password_last_used_md),
            ],
        },
        {
            "title": "IAM Access Keys",
            "resources": by_type["aws.iam.access_key"],
            "split_disabled": False,
            "columns": [
                ("User Name", _attr("user_name")),
                ("Key ID", _attr("key_id")),
                ("Status", _attr("status")),
                ("Age (days)", _attr("age_days")),
                ("Last Used", lambda r: (r["attributes"].get("last_used_date") or "never")[:10]),
            ],
        },
        {
            "title": "IAM Roles",
            "resources": by_type["aws.iam.role"],
            "split_disabled": False,
            "columns": [
                ("Role Name", _attr("role_name")),
                ("Service-Linked", lambda r: "yes" if r["attributes"].get("is_service_linked") else "no"),
                ("Public Trust", lambda r: "yes" if r["attributes"].get("trust_policy_public") else "no"),
            ],
        },
        {
            "title": "IAM Bindings",
            "resources": by_type["aws.iam.binding"],
            "split_disabled": False,
            "custom_render": "aws_bindings",
            "columns": [
                ("Principal Type", _attr("principal_type")),
                ("Principal", _attr("principal")),
                ("Policy", _attr("policy_name")),
                ("Inline", lambda r: "yes" if "inline" in r.get("tags", []) else "no"),
            ],
        },
        {
            "title": "IAM Access Advisor",
            "resources": by_type["aws.iam.access_advisor"],
            "split_disabled": False,
            "columns": [
                ("User Name", _attr("user_name")),
                ("Last Activity", lambda r: (r["attributes"].get("last_activity") or "never")[:10]),
                ("Services Used", _attr("services_used_count")),
                ("Services Granted", _attr("services_granted_count")),
            ],
        },
        {
            "title": "Security Groups",
            "resources": by_type["aws.ec2.security_group"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Group ID", _attr("group_id")),
                ("Group Name", _attr("group_name")),
                ("VPC", _attr("vpc_id")),
                ("Ingress Rules", lambda r: "; ".join(r["attributes"].get("ingress_rules", []))),
            ],
            "columns_md": [
                ("Region", _attr("region")),
                ("Group ID", _attr("group_id")),
                ("Group Name", _attr("group_name")),
                ("VPC", _attr("vpc_id")),
                ("Ingress Rules", lambda r: "<br>".join(r["attributes"].get("ingress_rules", []))),
            ],
        },
        {
            "title": "EC2 Key Pairs",
            "resources": by_type["aws.ec2.key_pair"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Key Name", _attr("key_name")),
                ("Type", _attr("key_type")),
                ("Fingerprint", _attr("fingerprint")),
                ("Created", lambda r: (r["attributes"].get("create_time") or "")[:10]),
            ],
        },
        {
            "title": "S3 Buckets",
            "resources": by_type["aws.s3.bucket"],
            "split_disabled": False,
            "columns": [
                ("Bucket Name", _attr("bucket_name")),
                ("Public (ACL)", lambda r: "yes" if r["attributes"].get("is_public_acl") else "no"),
                ("Public (Policy)", lambda r: "yes" if r["attributes"].get("is_public_policy") else "no"),
                ("Block Public Access", lambda r: "yes" if r["attributes"].get("block_public_access_enabled") else "no"),
            ],
            "columns_md": [
                ("Bucket Name", _attr("bucket_name")),
                ("Public (ACL)", lambda r: _fmt_bool_red_if_md(r["attributes"].get("is_public_acl"), red_if=True)),
                ("Public (Policy)", lambda r: _fmt_bool_red_if_md(r["attributes"].get("is_public_policy"), red_if=True)),
                ("Block Public Access", lambda r: _fmt_bool_red_if_md(r["attributes"].get("block_public_access_enabled"), red_if=False)),
            ],
        },
        {
            "title": "API Gateway Keys",
            "resources": by_type["aws.apigateway.key"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Name", _attr("name")),
                ("Enabled", lambda r: "yes" if r["attributes"].get("enabled") else "no"),
                ("Created", lambda r: (r["attributes"].get("created_date") or "")[:10]),
                ("Stage Keys", lambda r: str(len(r["attributes"].get("stage_keys", [])))),
            ],
        },
        {
            "title": "Security Hub Findings",
            "resources": by_type["aws.securityhub.finding"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Title", _attr("title")),
                ("Workflow State", _attr("workflow_state")),
                ("Compliance", _attr("compliance_status")),
            ],
        },
        {
            "title": "GuardDuty Findings",
            "resources": by_type["aws.guardduty.finding"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Title", _attr("title")),
                ("Type", _attr("finding_type")),
                ("Resource Type", _attr("resource_type")),
            ],
        },
        {
            "title": "Access Analyzer Findings",
            "resources": by_type["aws.accessanalyzer.finding"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Resource", _attr("resource")),
                ("Resource Type", _attr("resource_type")),
                ("Public", lambda r: "yes" if r["attributes"].get("is_public") else "no"),
            ],
        },
        {
            "title": "Resource Explorer Inventory",
            "resources": by_type["aws.resourceexplorer.resource_count"],
            "split_disabled": False,
            "sort_fn": lambda items: sorted(
                items, key=lambda r: (r["attributes"].get("region") or "", r["attributes"].get("resource_type") or "")
            ),
            "columns": [
                ("Region", _attr("region")),
                ("Resource Type", _attr("resource_type")),
                ("Count", _attr("count")),
            ],
        },
        {
            "title": "CloudTrail",
            "resources": by_type["aws.cloudtrail.trail"],
            "split_disabled": False,
            "columns": [
                ("Name", _attr("name")),
                ("Logging", lambda r: "yes" if r["attributes"].get("is_logging") else "no"),
                ("Multi-Region", lambda r: "yes" if r["attributes"].get("is_multi_region") else "no"),
                ("Log File Validation", lambda r: "yes" if r["attributes"].get("log_file_validation_enabled") else "no"),
                ("S3 Bucket", _attr("s3_bucket")),
            ],
        },
        {
            "title": "AWS Config Recorder",
            "resources": by_type["aws.config.recorder"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Name", _attr("name")),
                ("Recording", lambda r: "yes" if r["attributes"].get("recording") else "no"),
                ("All Supported", lambda r: "yes" if r["attributes"].get("all_supported") else "no"),
                ("Last Status", _attr("last_status")),
            ],
        },
        {
            "title": "IAM Password Policy",
            "resources": by_type["aws.iam.password_policy"],
            "split_disabled": False,
            "columns": [
                ("Configured", lambda r: "yes" if r["attributes"].get("configured") else "no"),
                ("Min Length", _attr("minimum_length")),
                ("Requires Symbols", lambda r: "yes" if r["attributes"].get("require_symbols") else "no"),
                ("Requires Numbers", lambda r: "yes" if r["attributes"].get("require_numbers") else "no"),
                ("Max Age (days)", _attr("max_password_age")),
            ],
        },
        {
            "title": "KMS Keys",
            "resources": by_type["aws.kms.key"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Key ID", _attr("key_id")),
                ("Description", _attr("description")),
                ("Rotation Enabled", lambda r: "yes" if r["attributes"].get("rotation_enabled") else "no"),
            ],
        },
        {
            "title": "RDS Instances",
            "resources": by_type["aws.rds.instance"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Identifier", _attr("identifier")),
                ("Engine", _attr("engine")),
                ("Publicly Accessible", lambda r: "yes" if r["attributes"].get("publicly_accessible") else "no"),
                ("Storage Encrypted", lambda r: "yes" if r["attributes"].get("storage_encrypted") else "no"),
            ],
        },
        {
            "title": "EBS Default Encryption",
            "resources": by_type["aws.ec2.ebs_default_encryption"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("Enabled", lambda r: "yes" if r["attributes"].get("enabled") else "no"),
            ],
        },
        {
            "title": "VPCs",
            "resources": by_type["aws.ec2.vpc"],
            "split_disabled": False,
            "columns": [
                ("Region", _attr("region")),
                ("VPC ID", _attr("vpc_id")),
                ("Default", lambda r: "yes" if r["attributes"].get("is_default") else "no"),
                ("Has Flow Log", lambda r: "yes" if r["attributes"].get("has_flow_log") else "no"),
            ],
        },
    ]
    if other:
        chapters.append({
            "title": "Other Findings",
            "resources": other,
            "split_disabled": False,
            "columns": [("Type", lambda r: r["type"]), ("ID", lambda r: r["id"]), ("Tags", lambda r: ", ".join(r.get("tags", [])))],
        })
    return chapters


TRELLO_KNOWN_TYPES = {
    "trello.board",
    "trello.board_member",
    "trello.org_member",
}


def _trello_chapters(resources):
    """Buckets Trello resources into named report chapters, the same
    dedicated-chapter treatment GCP/Bitbucket/AWS get, instead of the flat
    "Current findings (N total)" list of bare IDs the generic fallback
    renders for any provider with no chapter definition."""
    by_type = {t: [] for t in TRELLO_KNOWN_TYPES}
    other = []
    for r in resources:
        if r["type"] in by_type:
            by_type[r["type"]].append(r)
        else:
            other.append(r)

    board_names_by_id = {b["attributes"].get("board_id"): b["attributes"].get("name") for b in by_type["trello.board"]}
    board_info_by_id = {
        b["attributes"].get("board_id"): {"name": b["attributes"].get("name"), "closed": b["attributes"].get("closed")}
        for b in by_type["trello.board"]
    }

    chapters = [
        {
            "title": "Organization Members",
            "resources": by_type["trello.org_member"],
            "split_disabled": False,
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("last_active") or "", reverse=True),
            "columns": [
                ("Name", lambda r: r["attributes"].get("full_name") or r["attributes"].get("username") or "(unknown)"),
                ("Member Type", _attr("member_type")),
                ("Unconfirmed", lambda r: "yes" if r["attributes"].get("unconfirmed") else "no"),
                ("Deactivated", lambda r: "yes" if r["attributes"].get("deactivated") else "no"),
                ("Last Active", lambda r: (r["attributes"].get("last_active") or "never")[:10]),
            ],
            "columns_md": [
                ("Name", lambda r: r["attributes"].get("full_name") or r["attributes"].get("username") or "(unknown)"),
                ("Member Type", lambda r: _fmt_trello_permission_md(r["attributes"].get("member_type"))),
                ("Unconfirmed", lambda r: "yes" if r["attributes"].get("unconfirmed") else "no"),
                ("Deactivated", lambda r: "yes" if r["attributes"].get("deactivated") else "no"),
                ("Last Active", lambda r: _fmt_trello_last_active_md(r["attributes"].get("last_active"))),
            ],
        },
        {
            "title": "Boards",
            "resources": by_type["trello.board"],
            "split_disabled": True,
            "gray_disabled": True,
            "disabled_predicate": lambda r: bool(r["attributes"].get("closed")),
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("date_last_activity") or "", reverse=True),
            "columns": [
                ("Name", _attr("name")),
                ("Visibility", _attr("visibility")),
                ("Last Activity", lambda r: (r["attributes"].get("date_last_activity") or "never")[:10]),
            ],
            "columns_md": [
                ("Name", _attr("name")),
                ("Visibility", _attr("visibility")),
                ("Last Activity", lambda r: _fmt_trello_last_active_md(r["attributes"].get("date_last_activity"))),
            ],
        },
        {
            "title": "Board Members",
            "resources": by_type["trello.board_member"],
            "split_disabled": False,
            "custom_render": "trello_members",
            "board_info_by_id": board_info_by_id,
            "columns": [("Member", lambda r: r["attributes"].get("full_name") or r["attributes"].get("username")), ("Board", _attr("board_id")), ("Permission", _attr("membership_type"))],
        },
    ]
    if other:
        chapters.append({
            "title": "Other Findings",
            "resources": other,
            "split_disabled": False,
            "columns": [("Type", lambda r: r["type"]), ("ID", lambda r: r["id"]), ("Tags", lambda r: ", ".join(r.get("tags", [])))],
        })
    return chapters


GSUITE_STALE_LOGIN_DAYS = 180  # ~6 months, matches PASSWORD_STALE_DAYS elsewhere


def _fmt_bool_red_if_md(value, red_if):
    """Bold-reds a yes/no cell when its value matches the "bad" condition
    (red_if) - e.g. 2FA columns render bold red on "no", admin columns don't
    need this since holding admin isn't itself bad."""
    text = "yes" if value else "no"
    if value == red_if:
        return f'**<span style="color:red">{text}</span>**'
    return text


def _fmt_gsuite_last_login_md(r):
    a = r["attributes"]
    if a.get("suspended"):
        return (a.get("last_login") or "never")[:10]
    age = a.get("login_age_days")
    formatted = (a.get("last_login") or "never")[:10]
    if age is not None and age > GSUITE_STALE_LOGIN_DAYS:
        return f'<span style="color:red">{formatted}</span>'
    return formatted


# Scope substrings considered low-risk/expected noise for a normal OAuth
# grant (basic identity/login and any read-only scope) - anything else is
# a real access grant worth an operator's attention, so gets highlighted
# rather than blending into routine sign-in scopes.
_OAUTH_SAFE_SCOPE_SUBSTRINGS = ("readonly", "userinfo.email", "userinfo.profile", "oauthlogin")


def _is_safe_oauth_scope(scope):
    s = (scope or "").lower()
    if s == "openid":
        return True
    return any(substr in s for substr in _OAUTH_SAFE_SCOPE_SUBSTRINGS)


def _shorten_oauth_scope(scope):
    """Displays just the meaningful tail of a scope URL (e.g. "userinfo.email"
    instead of "https://www.googleapis.com/auth/userinfo.email") - the
    "https://www.googleapis.com/auth/" (or similar) prefix is the same
    across nearly every scope and just adds noise to an already-dense cell."""
    scope = scope or ""
    return scope.rsplit("/", 1)[-1] if "/" in scope else scope


def _fmt_oauth_scope_md(scope):
    """Classifies safety against the full scope string (not the shortened
    display form, to avoid a shortened tail accidentally colliding with an
    unrelated API's scope name) but displays the shortened tail."""
    text = _shorten_oauth_scope(scope)
    if _is_safe_oauth_scope(scope):
        return text
    return f'<span style="color:orange">{text}</span>'


def _merge_oauth_grants_by_app_and_scopes(grants):
    """Collapses repeat grants of the SAME app with the SAME scope set (just
    made at different times - e.g. re-authorizing Chrome every so often) into
    one entry spanning the latest-to-earliest occurrence, instead of
    repeating an otherwise-identical line once per timestamp. Grants to
    different apps, or the same app with a different scope set, stay as
    separate entries. `grants` must already be sorted newest-first - that
    order is what determines which entries are "new" as they're encountered
    and is preserved in the returned list."""
    merged = {}
    order = []
    for g in grants:
        key = (g["app_name"], tuple(sorted(g["scopes"])))
        if key not in merged:
            merged[key] = {"app_name": g["app_name"], "scopes": g["scopes"], "times": [], "severity": g["severity"]}
            order.append(key)
        merged[key]["times"].append(g["time"])

    result = []
    for key in order:
        entry = merged[key]
        times = sorted((t for t in entry["times"] if t), reverse=True)
        result.append({
            "app_name": entry["app_name"], "scopes": entry["scopes"], "severity": entry["severity"],
            "latest": times[0] if times else None,
            "earliest": times[-1] if times else None,
            "occurrences": len(entry["times"]),
        })
    return result


def _group_gsuite_oauth_grants_by_user(resources, order):
    """Collapses one-row-per-grant gsuite.oauth_grant resources into one
    entry per actor (the user who granted access) with every distinct
    (app, scopes) grant they've made - repeat grants of the same app/scopes
    at different times are merged into one entry via
    _merge_oauth_grants_by_app_and_scopes rather than listed once per
    timestamp."""
    users = {}
    for r in resources:
        a = r["attributes"]
        actor = a.get("actor_email") or "(unknown)"
        users.setdefault(actor, []).append({
            "time": a.get("time"), "app_name": a.get("app_name"),
            "scopes": a.get("scopes") or [], "severity": r.get("severity", "info"),
        })

    groups = []
    for actor, grants in users.items():
        grants = sorted(grants, key=lambda g: g["time"] or "", reverse=True)
        merged_grants = _merge_oauth_grants_by_app_and_scopes(grants)
        worst_severity = min((g["severity"] for g in grants), key=lambda s: _severity_rank(s, order), default="info")
        groups.append({"actor": actor, "grants": merged_grants, "severity": worst_severity})

    groups.sort(key=lambda g: (_severity_rank(g["severity"], order), g["actor"]))
    return groups


GSUITE_KNOWN_TYPES = {
    "gsuite.user",
    "gsuite.admin_summary",
    "gsuite.group",
    "gsuite.org_unit",
    "gsuite.mobile_device",
    "gsuite.login_event",
    "gsuite.oauth_grant",
}


def _gsuite_chapters(resources):
    """Buckets Google Workspace resources into named report chapters, the
    same dedicated-chapter treatment every other provider gets."""
    by_type = {t: [] for t in GSUITE_KNOWN_TYPES}
    other = []
    for r in resources:
        if r["type"] in by_type:
            by_type[r["type"]].append(r)
        else:
            other.append(r)

    chapters = [
        {
            "title": "Admin Summary",
            "resources": by_type["gsuite.admin_summary"],
            "split_disabled": False,
            "columns": [
                ("Super Admin Count", _attr("super_admin_count")),
                ("Super Admins", lambda r: ", ".join(r["attributes"].get("super_admin_emails", [])) or "none"),
                ("Delegated Admin Count", _attr("delegated_admin_count")),
            ],
        },
        {
            "title": "Users",
            "resources": by_type["gsuite.user"],
            "split_disabled": True,
            "gray_disabled": True,
            "disabled_predicate": lambda r: bool(r["attributes"].get("suspended")),
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("email") or ""),
            "columns": [
                ("Email", _attr("email")),
                ("Name", _attr("full_name")),
                ("Admin", lambda r: "yes" if (r["attributes"].get("is_admin") or r["attributes"].get("is_delegated_admin")) else "no"),
                ("2FA Enrolled", lambda r: "yes" if r["attributes"].get("is_enrolled_2sv") else "no"),
                ("2FA Enforced", lambda r: "yes" if r["attributes"].get("is_enforced_2sv") else "no"),
                ("Last Login", lambda r: (r["attributes"].get("last_login") or "never")[:10]),
                ("Org Unit", _attr("org_unit_path")),
            ],
            "columns_md": [
                ("Email", _attr("email")),
                ("Name", _attr("full_name")),
                ("Admin", lambda r: _fmt_bool_red_if_md(r["attributes"].get("is_admin") or r["attributes"].get("is_delegated_admin"), red_if=True)),
                ("2FA Enrolled", lambda r: _fmt_bool_red_if_md(r["attributes"].get("is_enrolled_2sv"), red_if=False)),
                ("2FA Enforced", lambda r: _fmt_bool_red_if_md(r["attributes"].get("is_enforced_2sv"), red_if=False)),
                ("Last Login", _fmt_gsuite_last_login_md),
                ("Org Unit", _attr("org_unit_path")),
            ],
        },
        {
            "title": "Groups",
            "resources": by_type["gsuite.group"],
            "split_disabled": False,
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("email") or ""),
            "columns": [
                ("Email", _attr("email")),
                ("Name", _attr("name")),
                ("Members", _attr("direct_members_count")),
                ("Owners", lambda r: ", ".join(r["attributes"].get("owners", [])) or "none"),
                ("Managers", lambda r: ", ".join(r["attributes"].get("managers", [])) or "none"),
            ],
        },
        {
            "title": "Org Units",
            "resources": by_type["gsuite.org_unit"],
            "split_disabled": False,
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("org_unit_path") or ""),
            "columns": [
                ("Path", _attr("org_unit_path")),
                ("Name", _attr("name")),
                ("Description", _attr("description")),
                ("Parent", _attr("parent_org_unit_path")),
            ],
        },
        {
            "title": "Mobile Devices",
            "resources": by_type["gsuite.mobile_device"],
            "split_disabled": False,
            "custom_render": "gsuite_mobile_devices",
        },
        {
            "title": "Suspicious Login Events",
            "resources": by_type["gsuite.login_event"],
            "split_disabled": False,
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("time") or "", reverse=True),
            "columns": [
                ("Time", lambda r: (r["attributes"].get("time") or "")[:19]),
                ("Event", _attr("event_name")),
                ("Actor", _attr("actor_email")),
                ("IP", _attr("ip_address")),
                ("Region", _attr("region_code")),
            ],
        },
        {
            "title": "OAuth App Grants",
            "resources": by_type["gsuite.oauth_grant"],
            "split_disabled": False,
            "custom_render": "gsuite_oauth_grants",
        },
    ]
    if other:
        chapters.append({
            "title": "Other Findings",
            "resources": other,
            "split_disabled": False,
            "columns": [("Type", lambda r: r["type"]), ("ID", lambda r: r["id"]), ("Tags", lambda r: ", ".join(r.get("tags", [])))],
        })
    return chapters


CONFLUENCE_KNOWN_TYPES = {
    "confluence.space",
    "confluence.space_permission",
    "confluence.other_spaces_summary",
}


def _fmt_confluence_anonymous_md(r):
    ops = r["attributes"].get("anonymous_operations") or []
    if not ops:
        return "no"
    return f'**<span style="color:red">yes ({", ".join(ops)})</span>**'


def _fmt_confluence_operations_md(r):
    ops = r["attributes"].get("operations") or []
    text = ", ".join(ops)
    if any(op.startswith("administer:") for op in ops):
        return f"**<span style=\"color:red\">{text}</span>**"
    return text


def _confluence_is_deactivated(r):
    return "(Deactivated)" in (r["attributes"].get("subject") or "")


def _confluence_sort_by_operations(items):
    return sorted(items, key=lambda r: ", ".join(sorted(r["attributes"].get("operations", []))))


def _confluence_permission_columns(md):
    return [
        ("Space", _attr("space_key")),
        ("Subject", _attr("subject")),
        ("Type", _attr("subject_type")),
        ("Operations", _fmt_confluence_operations_md if md else (lambda r: ", ".join(r["attributes"].get("operations", [])))),
        ("Via", lambda r: ", ".join(r["attributes"].get("via", []))),
    ]


def _confluence_chapters(resources):
    """Buckets Confluence resources into named report chapters, the same
    dedicated-chapter treatment every other provider gets."""
    by_type = {t: [] for t in CONFLUENCE_KNOWN_TYPES}
    other = []
    for r in resources:
        if r["type"] in by_type:
            by_type[r["type"]].append(r)
        else:
            other.append(r)

    chapters = [
        {
            "title": "Spaces",
            "resources": by_type["confluence.space"],
            "split_disabled": False,
            "sort_fn": lambda items: sorted(items, key=lambda r: r["attributes"].get("key") or ""),
            "columns": [
                ("Key", _attr("key")),
                ("Name", _attr("name")),
                ("Type", _attr("space_type")),
                ("Status", _attr("status")),
                ("Anonymous Access", lambda r: "yes" if r["attributes"].get("anonymous_access") else "no"),
                ("Admins", lambda r: ", ".join(r["attributes"].get("admins", [])) or "none"),
            ],
            "columns_md": [
                ("Key", _attr("key")),
                ("Name", _attr("name")),
                ("Type", _attr("space_type")),
                ("Status", _attr("status")),
                ("Anonymous Access", _fmt_confluence_anonymous_md),
                ("Admins", lambda r: ", ".join(r["attributes"].get("admins", [])) or "none"),
            ],
        },
    ]
    if by_type["confluence.space_permission"]:
        admin_group_names = {"group:administrators", "group:wiki-admin"}
        is_admin_group = lambda r: bool(admin_group_names & set(r["attributes"].get("via") or []))
        admins_group = [r for r in by_type["confluence.space_permission"] if is_admin_group(r)]
        other_group = [r for r in by_type["confluence.space_permission"] if not is_admin_group(r)]
        if other_group:
            chapters.append({
                "title": "Space Permissions - Other",
                "resources": other_group,
                "split_disabled": True,
                "gray_disabled": True,
                "disabled_predicate": _confluence_is_deactivated,
                "sort_fn": _confluence_sort_by_operations,
                "columns": _confluence_permission_columns(md=False),
                "columns_md": _confluence_permission_columns(md=True),
            })
        if admins_group:
            chapters.append({
                "title": "Space Permissions - group:administrators",
                "resources": admins_group,
                "split_disabled": True,
                "gray_disabled": True,
                "disabled_predicate": _confluence_is_deactivated,
                "sort_fn": _confluence_sort_by_operations,
                "columns": _confluence_permission_columns(md=False),
                "columns_md": _confluence_permission_columns(md=True),
            })
    if by_type["confluence.other_spaces_summary"]:
        chapters.append({
            "title": "Other Authorized Spaces",
            "resources": by_type["confluence.other_spaces_summary"],
            "split_disabled": False,
            "columns": [
                ("Note", lambda r: f"Detected another {r['attributes'].get('other_space_count', 0)} authorized space(s) under this account (not scanned in detail - see main_space in config)"),
            ],
        })
    if other:
        chapters.append({
            "title": "Other Findings",
            "resources": other,
            "split_disabled": False,
            "columns": [("Type", lambda r: r["type"]), ("ID", lambda r: r["id"]), ("Tags", lambda r: ", ".join(r.get("tags", [])))],
        })
    return chapters


def _resolve_chapter_groups(chapter, order):
    """Returns [(subtitle, sorted_resources), ...] - two groups (enabled
    shown first, then disabled) if split_disabled, else one group.

    Defaults to the `disabled` attribute, but a chapter can supply its own
    `disabled_predicate(resource) -> bool` for resource types that spell
    the same enabled/disabled distinction differently (e.g. a webhook's
    `active` flag). Sorts worst-severity-first by default; a chapter can
    supply `sort_fn(items) -> items` to sort some other way (e.g. Repos by
    name, since severity there is just public/private and floods all the
    public repos to the top)."""
    resources = chapter["resources"]
    sort_fn = chapter.get("sort_fn", lambda items: _sorted_by_severity(items, order))
    if chapter["split_disabled"]:
        is_disabled = chapter.get("disabled_predicate", lambda r: bool(r["attributes"].get("disabled")))
        enabled = [r for r in resources if not is_disabled(r)]
        disabled = [r for r in resources if is_disabled(r)]
        return [
            (f"{chapter['title']} (enabled)", sort_fn(enabled)),
            (f"{chapter['title']} (disabled)", sort_fn(disabled)),
        ]
    return [(chapter["title"], sort_fn(resources))]


def _split_resource_prefix(resource_name):
    """Splits a full SCC resource path into (display_prefix, short_name) for
    bullet rendering: the location segment (zone/region/location) is
    normalized to a wildcard in the prefix, same as _scc_resource_stem,
    since a table's resource_list commonly mixes a wildcarded fleet
    ("zones/*/instances/foo-*") with a lone instance in one concrete zone
    ("zones/us-central1-a/instances/bar") - without normalizing, those two
    would never share a prefix even though grouping them under one is the
    whole point of this display."""
    if not resource_name or "/" not in resource_name:
        return "", resource_name
    prefix, _, short_name = resource_name.rpartition("/")
    prefix = _LOCATION_SEGMENT_RE.sub(lambda m: f"/{m.group(1)}/*", prefix, count=1)
    if prefix.startswith("//"):
        prefix = prefix[2:]
    return prefix + "/", short_name


def _group_resources_by_prefix(resource_list):
    """Returns [(prefix, [short_name, ...]), ...] sorted by prefix, each
    short_name list sorted - the common-prefix bucketing that lets a
    resource table show its shared path once instead of repeating it on
    every line."""
    by_prefix = {}
    for resource in resource_list:
        prefix, short_name = _split_resource_prefix(resource)
        by_prefix.setdefault(prefix, []).append(short_name)
    return sorted((prefix, sorted(names)) for prefix, names in by_prefix.items())


def _render_scc_console(findings, order, top_n):
    by_section = _group_scc_findings_by_section(findings, order)
    total_groups = sum(len(groups) for _, groups in by_section)
    safe_print(f"  Security Command Center Findings ({len(findings)} findings across {total_groups} resource groups, {len(by_section)} sections):")
    for section_title, groups in by_section:
        safe_print(f"    -- {section_title} ({len(groups)} groups) --")
        for g in groups[:top_n]:
            cat_summary = ", ".join(f"{c['category']} x{c['count']} ({c['severity']})" for c in g["categories"])
            for prefix, short_names in _group_resources_by_prefix(g["resource_list"]):
                safe_print(f'          "{prefix}"')
                for short_name in short_names:
                    safe_print(f"            - {short_name}")
            safe_print(f"      ({g['severity']}) {cat_summary}")
        if len(groups) > top_n:
            safe_print(f"      ... +{len(groups) - top_n} more in this section, see full report")


def _render_scc_markdown(lines, findings, order):
    by_section = _group_scc_findings_by_section(findings, order)
    total_groups = sum(len(groups) for _, groups in by_section)
    lines.append(f"### Security Command Center Findings ({len(findings)} findings across {total_groups} resource groups, {len(by_section)} sections)")
    lines.append("")
    if not by_section:
        lines.append("_None._")
        lines.append("")
        return
    for section_title, groups in by_section:
        lines.append(f"### {section_title} ({len(groups)} groups)")
        lines.append("")
        for i, g in enumerate(groups):
            for prefix, short_names in _group_resources_by_prefix(g["resource_list"]):
                lines.append(f'**"{prefix}" :**')
                for short_name in short_names:
                    lines.append(f"- {short_name}")
                lines.append("")
            lines.append("| Category | Count | Severity |")
            lines.append("|---|---|---|")
            for c in g["categories"]:
                lines.append(f"| {c['category']} | {c['count']} | {_fmt_severity_md(c['severity'])} |")
            lines.append("")
            if i < len(groups) - 1:
                lines.append("---")
                lines.append("")


def _render_iam_users_console(resources, order, top_n):
    groups = _group_iam_bindings_by_member(resources, order)
    safe_print(f"  IAM Bindings - Users ({len(groups)} users):")
    for g in groups[:top_n]:
        safe_print(f"    ({g['severity']}) {g['member']}")
        for r in g["roles"]:
            safe_print(f"        - {r['role']} ({r['severity']})")
            for perm in (r.get("included_permissions") or []):
                safe_print(f"            * {perm}")
    if len(groups) > top_n:
        safe_print(f"    ... +{len(groups) - top_n} more, see full report")


def _render_iam_users_markdown(lines, resources, order):
    groups = _group_iam_bindings_by_member(resources, order)
    lines.append(f"### IAM Bindings - Users ({len(groups)} users)")
    lines.append("")
    if not groups:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Severity | User | Roles |")
    lines.append("|---|---|---|")
    for g in groups:
        role_lines = []
        for r in g["roles"]:
            role_lines.append(f"{r['role']} ({_fmt_severity_md(r['severity'])})")
            for perm in (r.get("included_permissions") or []):
                role_lines.append(f"&nbsp;&nbsp;&nbsp;&nbsp;- {perm}")
        roles = "<br>".join(role_lines)
        lines.append(f"| {_fmt_severity_md(g['severity'])} | {g['member']} | {roles} |")
    lines.append("")


def _render_bitbucket_principals_console(resources, order, top_n):
    groups = _group_bitbucket_permissions_by_principal(resources, order)
    safe_print(f"  Repo Permissions ({len(groups)} principals):")
    for g in groups[:top_n]:
        safe_print(f"    ({g['severity']}) {g['principal']}")
        for gr in g["grants"]:
            safe_print(f"        - {gr['workspace']}/{gr['repo_slug']} ({gr['permission']})")
    if len(groups) > top_n:
        safe_print(f"    ... +{len(groups) - top_n} more, see full report")


def _render_bitbucket_principals_markdown(lines, resources, order):
    groups = _group_bitbucket_permissions_by_principal(resources, order)
    lines.append(f"### Repo Permissions ({len(groups)} principals)")
    lines.append("")
    if not groups:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Severity | Principal | Repo Access |")
    lines.append("|---|---|---|")
    for g in groups:
        grants = "<br>".join(
            f"{gr['workspace']}/{gr['repo_slug']} ({_fmt_bb_permission_md(gr['permission'])})" for gr in g["grants"]
        )
        lines.append(f"| {_fmt_severity_md(g['severity'])} | {g['principal']} | {grants} |")
    lines.append("")


def _render_gsuite_mobile_devices_console(resources, order, top_n):
    groups = _group_gsuite_mobile_devices_by_owner(resources, order)
    safe_print(f"  Mobile Devices ({len(groups)} owners):")
    for g in groups[:top_n]:
        safe_print(f"    ({g['severity']}) {g['owner']}")
        for d in g["devices"]:
            last_sync = (d["last_sync"] or "never")[:10]
            safe_print(
                f"        - {d['model']} | OS: {d['os']} | Status: {d['status']} | "
                f"Compromised: {d['compromised_status']} | Encrypted: {d['encryption_status']} | "
                f"Password Set: {d['password_status']} | Last Sync: {last_sync}"
            )
    if len(groups) > top_n:
        safe_print(f"    ... +{len(groups) - top_n} more, see full report")


def _render_gsuite_mobile_devices_markdown(lines, resources, order):
    groups = _group_gsuite_mobile_devices_by_owner(resources, order)
    lines.append(f"### Mobile Devices ({len(groups)} owners)")
    lines.append("")
    if not groups:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Severity | Owner | Devices |")
    lines.append("|---|---|---|")
    for g in groups:
        device_lines = []
        for d in g["devices"]:
            last_sync = (d["last_sync"] or "never")[:10]
            text = (
                f"{d['model']} (OS: {d['os']}, Status: {d['status']}, "
                f"Compromised: {d['compromised_status']}, Encrypted: {d['encryption_status']}, "
                f"Password Set: {d['password_status']}, Last Sync: {last_sync})"
            )
            age = d["last_sync_age_days"]
            is_stale = age is None or age > MOBILE_DEVICE_STALE_SYNC_DAYS
            if is_stale:
                text = f'<span style="background-color:#d9d9d9;">{text}</span>'
            device_lines.append(text)
        lines.append(f"| {_fmt_severity_md(g['severity'])} | {g['owner']} | {'<br>'.join(device_lines)} |")
    lines.append("")


def _fmt_oauth_time_range(grant):
    latest = (grant["latest"] or "")[:19]
    if grant["occurrences"] <= 1:
        return latest
    earliest = (grant["earliest"] or "")[:19]
    return f"{latest} ( to {earliest} )"


def _render_gsuite_oauth_grants_console(resources, order, top_n):
    groups = _group_gsuite_oauth_grants_by_user(resources, order)
    safe_print(f"  OAuth App Grants ({len(groups)} users):")
    for g in groups[:top_n]:
        safe_print(f"    ({g['severity']}) {g['actor']}")
        for grant in g["grants"]:
            time_range = _fmt_oauth_time_range(grant)
            scopes = ", ".join(_shorten_oauth_scope(s) for s in grant["scopes"]) or "none"
            safe_print(f"        - {time_range} | App: {grant['app_name']} | Scopes: {scopes}")
    if len(groups) > top_n:
        safe_print(f"    ... +{len(groups) - top_n} more, see full report")


def _render_gsuite_oauth_grants_markdown(lines, resources, order):
    groups = _group_gsuite_oauth_grants_by_user(resources, order)
    lines.append(f"### OAuth App Grants ({len(groups)} users)")
    lines.append("")
    if not groups:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Severity | User | Grants |")
    lines.append("|---|---|---|")
    for g in groups:
        grant_lines = []
        for grant in g["grants"]:
            time_range = _fmt_oauth_time_range(grant)
            scopes = ", ".join(_fmt_oauth_scope_md(s) for s in grant["scopes"]) or "none"
            grant_lines.append(f"{time_range} - **{grant['app_name']}**: {scopes}")
        lines.append(f"| {_fmt_severity_md(g['severity'])} | {g['actor']} | {'<br>'.join(grant_lines)} |")
    lines.append("")


def _render_trello_members_console(resources, board_info_by_id, order, top_n):
    groups = _group_trello_board_members_by_member(resources, board_info_by_id, order)
    safe_print(f"  Board Members ({len(groups)} members):")
    for g in groups[:top_n]:
        last_active = (g["last_active"] or "never")[:10]
        safe_print(f"    ({g['severity']}) {g['member']} | Last Active: {last_active}")
        for b in g["boards"]:
            closed_note = " [closed]" if b["closed"] else ""
            safe_print(f"        - {b['board_name']}{closed_note} ({b['membership_type']})")
    if len(groups) > top_n:
        safe_print(f"    ... +{len(groups) - top_n} more, see full report")


def _render_trello_members_markdown(lines, resources, board_info_by_id, order):
    groups = _group_trello_board_members_by_member(resources, board_info_by_id, order)
    lines.append(f"### Board Members ({len(groups)} members)")
    lines.append("")
    if not groups:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Severity | Member | Last Active | Board Access |")
    lines.append("|---|---|---|---|")
    for g in groups:
        boards = "<br>".join(
            f'<span style="background-color:#d9d9d9;">{b["board_name"]} (closed) ({_fmt_trello_permission_md(b["membership_type"])})</span>'
            if b["closed"] else f'{b["board_name"]} ({_fmt_trello_permission_md(b["membership_type"])})'
            for b in g["boards"]
        )
        last_active = _fmt_trello_last_active_md(g["last_active"])
        lines.append(f"| {_fmt_severity_md(g['severity'])} | {g['member']} | {last_active} | {boards} |")
    lines.append("")


def _render_aws_bindings_console(resources, order, top_n):
    groups = _group_aws_bindings_by_principal(resources, order)
    safe_print(f"  IAM Bindings ({len(groups)} principals):")
    for g in groups[:top_n]:
        safe_print(f"    ({g['severity']}) {g['principal_type']}/{g['principal']}")
        for p in g["policies"]:
            inline_note = " (inline)" if p["is_inline"] else ""
            safe_print(f"        - {p['policy_name']}{inline_note} ({p['severity']})")
    if len(groups) > top_n:
        safe_print(f"    ... +{len(groups) - top_n} more, see full report")


def _render_aws_bindings_markdown(lines, resources, order):
    groups = _group_aws_bindings_by_principal(resources, order)
    lines.append(f"### IAM Bindings ({len(groups)} principals)")
    lines.append("")
    if not groups:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Severity | Principal Type | Principal | Policies |")
    lines.append("|---|---|---|---|")
    for g in groups:
        policies = "<br>".join(
            f"{p['policy_name']}{' (inline)' if p['is_inline'] else ''} ({_fmt_severity_md(p['severity'])})"
            for p in g["policies"]
        )
        lines.append(f"| {_fmt_severity_md(g['severity'])} | {g['principal_type']} | {g['principal']} | {policies} |")
    lines.append("")


def _fmt_bb_ssh_key_last_used(k):
    last_used = k.get("last_used")
    return f"{k['label'] or '(unlabeled)'} (Last Used: {(last_used or 'never')[:10]})"


def _render_bitbucket_ssh_keys_console(resources, order, top_n):
    groups = _group_bitbucket_ssh_keys_by_account(resources, order)
    safe_print(f"  Account SSH Keys ({len(groups)} accounts):")
    for g in groups[:top_n]:
        keys_summary = ", ".join(_fmt_bb_ssh_key_last_used(k) for k in g["keys"])
        safe_print(f"    ({g['severity']}) {g['account']} ({g['workspace']}) -> {keys_summary}")
    if len(groups) > top_n:
        safe_print(f"    ... +{len(groups) - top_n} more, see full report")


def _render_bitbucket_ssh_keys_markdown(lines, resources, order):
    groups = _group_bitbucket_ssh_keys_by_account(resources, order)
    lines.append(f"### Account SSH Keys ({len(groups)} accounts)")
    lines.append("")
    if not groups:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Severity | Account | Workspace | Keys |")
    lines.append("|---|---|---|---|")
    for g in groups:
        keys = ", ".join(_fmt_bb_ssh_key_last_used(k) for k in g["keys"])
        lines.append(f"| {_fmt_severity_md(g['severity'])} | {g['account']} | {g['workspace']} | {keys} |")
    lines.append("")


def _render_ssh_keys_console(resources, order, top_n):
    groups = _group_ssh_keys_by_username(resources, order)
    safe_print(f"  SSH Keys ({len(groups)} users):")
    for g in groups[:top_n]:
        safe_print(f"    ({g['severity']}) {g['username']}")
        for k in g["keys"]:
            safe_print(
                f"        - {k['scope']}:{k['scope_id']} | {k['algorithm']} | {k['fingerprint']} | "
                f"last used / source IP: not tracked by GCP for metadata-based SSH keys"
            )
    if len(groups) > top_n:
        safe_print(f"    ... +{len(groups) - top_n} more, see full report")


def _render_ssh_keys_markdown(lines, resources, order):
    groups = _group_ssh_keys_by_username(resources, order)
    lines.append(f"### SSH Keys ({len(groups)} users)")
    lines.append("")
    if not groups:
        lines.append("_None._")
        lines.append("")
        return
    lines.append(
        "_Last used timestamp / source IP is not exposed by the GCP API for metadata-based SSH keys "
        "(no login audit trail unless OS Login + audit logging is separately enabled)._"
    )
    lines.append("")
    for g in groups:
        lines.append("---")
        lines.append("")
        lines.append(f"**({_fmt_severity_md(g['severity'])}) {g['username']}**")
        lines.append("")
        lines.append("| Scope | Scope ID | Algorithm | Fingerprint |")
        lines.append("|---|---|---|---|")
        for k in g["keys"]:
            lines.append(f"| {k['scope']} | {k['scope_id']} | {k['algorithm']} | {k['fingerprint']} |")
        lines.append("")
        lines.append("---")
        lines.append("")
    lines.append("")


def _render_service_accounts_console(resources, keys_by_email, roles_by_email, order, top_n):
    for label, is_disabled in (("enabled", False), ("disabled", True)):
        group = _sorted_by_severity(
            [r for r in resources if bool(r["attributes"].get("disabled")) == is_disabled], order
        )
        safe_print(f"  Service Accounts ({label}) ({len(group)}):")
        for r in group[:top_n]:
            email = r["attributes"].get("email")
            safe_print(
                f"    ({r.get('severity', 'info')}) {email} | Has Key(s): {_fmt_has_keys(r)} | "
                f"Last Seen: {_fmt_seen_summary(r)}"
            )
            description = r["attributes"].get("description")
            if description:
                safe_print(f"        description: {description}")
            for k in keys_by_email.get(email, []):
                ka = k["attributes"]
                safe_print(
                    f"        - key {_fmt_key_id(k)} | type: {ka.get('key_type')} | "
                    f"age (days): {ka.get('age_days')} | created: {_fmt_created(k)}"
                )
            roles = sorted(roles_by_email.get(email, []), key=lambda x: _severity_rank(x["severity"], order))
            for role in roles:
                safe_print(f"        * permission: {role['role']} ({role['severity']})")
                for perm in (role.get("included_permissions") or []):
                    safe_print(f"            - {perm}")
        if len(group) > top_n:
            safe_print(f"    ... +{len(group) - top_n} more, see full report")


def _render_service_accounts_markdown(lines, resources, keys_by_email, roles_by_email, order):
    for label, is_disabled in (("enabled", False), ("disabled", True)):
        group = _sorted_by_severity(
            [r for r in resources if bool(r["attributes"].get("disabled")) == is_disabled], order
        )
        lines.append(f"### Service Accounts ({label}) ({len(group)})")
        lines.append("")
        if not group:
            lines.append("_None._")
            lines.append("")
            continue
        if is_disabled:
            lines.append('<div style="background-color:#d9d9d9;">')
            lines.append("")
        for r in group:
            email = r["attributes"].get("email")
            lines.append("---")
            lines.append("")
            sev_md = _fmt_severity_md(r.get('severity', 'info'), disabled=bool(r["attributes"].get("disabled")))
            lines.append(f"**({sev_md}) {email}** — Has Key(s): {_fmt_has_keys(r)}")
            lines.append("")
            description = r["attributes"].get("description")
            if description:
                lines.append(f"Description: {description}")
                lines.append("")
            lines.append(f"Last Seen: {_fmt_seen_summary(r)}")
            lines.append("")
            keys = keys_by_email.get(email, [])
            if keys:
                lines.append("| Key ID | Key Type | Age (days) | Created |")
                lines.append("|---|---|---|---|")
                for k in keys:
                    ka = k["attributes"]
                    lines.append(f"| {_fmt_key_id(k)} | {ka.get('key_type')} | {ka.get('age_days')} | {_fmt_created(k)} |")
                lines.append("")
            roles = sorted(roles_by_email.get(email, []), key=lambda x: _severity_rank(x["severity"], order))
            if roles:
                lines.append("Permissions:")
                lines.append("")
                for role in roles:
                    lines.append(f"- {role['role']} ({_fmt_severity_md(role['severity'])})")
                    for perm in (role.get("included_permissions") or []):
                        lines.append(f"  - {perm}")
                lines.append("")
            lines.append("---")
            lines.append("")
        if is_disabled:
            lines.append("</div>")
            lines.append("")
        lines.append("")


def _render_collapsible_groups_markdown(lines, items, md_columns, is_disabled_group, collapsible_groups):
    """Splits a chapter's items into named `<details>` sections by the first
    matching predicate (evaluated in order), with anything unmatched
    rendered as a normal table above them. For chapters whose resource list
    contains a large, low-signal fleet sharing a naming convention (e.g.
    hundreds of per-customer buckets) that would otherwise drown the
    handful of genuinely distinct resources in the same chapter."""
    remainder = list(items)
    named_groups = []
    for label, predicate in collapsible_groups:
        matched = [r for r in remainder if predicate(r)]
        remainder = [r for r in remainder if not predicate(r)]
        if matched:
            named_groups.append((label, matched))

    def render_table(rows):
        headers = ["Severity"] + [h for h, _ in md_columns]
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("|" + "---|" * len(headers))
        for r in rows:
            sev_cell = _fmt_severity_md(str(r.get("severity", "info")), disabled=is_disabled_group)
            cells = [sev_cell] + [str(fn(r)) for _, fn in md_columns]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")

    if remainder:
        render_table(remainder)
    else:
        lines.append("_None outside the grouped sections below._")
        lines.append("")

    for label, matched in named_groups:
        lines.append(f'<details><summary><span style="color:green">{label} ({len(matched)})</span></summary>')
        lines.append("")
        render_table(matched)
        lines.append("</details>")
        lines.append("")


def _render_chapters_console(chapters, order, top_n):
    for chapter in chapters:
        if chapter.get("custom_render") == "scc":
            _render_scc_console(chapter["resources"], order, top_n)
            continue
        if chapter.get("custom_render") == "iam_users":
            _render_iam_users_console(chapter["resources"], order, top_n)
            continue
        if chapter.get("custom_render") == "bitbucket_principals":
            _render_bitbucket_principals_console(chapter["resources"], order, top_n)
            continue
        if chapter.get("custom_render") == "bitbucket_ssh_keys":
            _render_bitbucket_ssh_keys_console(chapter["resources"], order, top_n)
            continue
        if chapter.get("custom_render") == "aws_bindings":
            _render_aws_bindings_console(chapter["resources"], order, top_n)
            continue
        if chapter.get("custom_render") == "trello_members":
            _render_trello_members_console(chapter["resources"], chapter["board_info_by_id"], order, top_n)
            continue
        if chapter.get("custom_render") == "ssh_keys":
            _render_ssh_keys_console(chapter["resources"], order, top_n)
            continue
        if chapter.get("custom_render") == "service_accounts":
            _render_service_accounts_console(
                chapter["resources"], chapter["keys_by_email"], chapter["roles_by_email"], order, top_n
            )
            continue
        if chapter.get("custom_render") == "gsuite_mobile_devices":
            _render_gsuite_mobile_devices_console(chapter["resources"], order, top_n)
            continue
        if chapter.get("custom_render") == "gsuite_oauth_grants":
            _render_gsuite_oauth_grants_console(chapter["resources"], order, top_n)
            continue
        for subtitle, items in _resolve_chapter_groups(chapter, order):
            safe_print(f"  {subtitle} ({len(items)}):")
            for r in items[:top_n]:
                parts = [f"{header}: {fn(r)}" for header, fn in chapter["columns"]]
                safe_print(f"    ({r.get('severity', 'info')}) " + " | ".join(parts))
            if len(items) > top_n:
                safe_print(f"    ... +{len(items) - top_n} more, see full report")


def _render_chapters_markdown(lines, chapters, order):
    for chapter in chapters:
        if chapter.get("custom_render") == "scc":
            _render_scc_markdown(lines, chapter["resources"], order)
            continue
        if chapter.get("custom_render") == "iam_users":
            _render_iam_users_markdown(lines, chapter["resources"], order)
            continue
        if chapter.get("custom_render") == "bitbucket_principals":
            _render_bitbucket_principals_markdown(lines, chapter["resources"], order)
            continue
        if chapter.get("custom_render") == "bitbucket_ssh_keys":
            _render_bitbucket_ssh_keys_markdown(lines, chapter["resources"], order)
            continue
        if chapter.get("custom_render") == "aws_bindings":
            _render_aws_bindings_markdown(lines, chapter["resources"], order)
            continue
        if chapter.get("custom_render") == "trello_members":
            _render_trello_members_markdown(lines, chapter["resources"], chapter["board_info_by_id"], order)
            continue
        if chapter.get("custom_render") == "ssh_keys":
            _render_ssh_keys_markdown(lines, chapter["resources"], order)
            continue
        if chapter.get("custom_render") == "service_accounts":
            _render_service_accounts_markdown(
                lines, chapter["resources"], chapter["keys_by_email"], chapter["roles_by_email"], order
            )
            continue
        if chapter.get("custom_render") == "gsuite_mobile_devices":
            _render_gsuite_mobile_devices_markdown(lines, chapter["resources"], order)
            continue
        if chapter.get("custom_render") == "gsuite_oauth_grants":
            _render_gsuite_oauth_grants_markdown(lines, chapter["resources"], order)
            continue
        for subtitle, items in _resolve_chapter_groups(chapter, order):
            is_disabled_group = subtitle.endswith("(disabled)")
            is_gray = chapter.get("gray_disabled") and is_disabled_group
            lines.append(f"### {subtitle} ({len(items)})")
            lines.append("")
            if is_gray:
                lines.append('<div style="background-color:#d9d9d9;">')
                lines.append("")
            if not items:
                lines.append("_None._")
                lines.append("")
            else:
                md_columns = chapter.get("columns_md", chapter["columns"])
                collapsible_groups = chapter.get("collapsible_groups")
                if collapsible_groups:
                    _render_collapsible_groups_markdown(lines, items, md_columns, is_disabled_group, collapsible_groups)
                else:
                    headers = ["Severity"] + [h for h, _ in md_columns]
                    lines.append("| " + " | ".join(headers) + " |")
                    lines.append("|" + "---|" * len(headers))
                    for r in items:
                        sev_cell = _fmt_severity_md(str(r.get("severity", "info")), disabled=is_disabled_group)
                        cells = [sev_cell] + [str(fn(r)) for _, fn in md_columns]
                        lines.append("| " + " | ".join(cells) + " |")
                    lines.append("")
            if is_gray:
                lines.append("</div>")
                lines.append("")


# --- Main renderers ----------------------------------------------------------

def render_console(results, config):
    order = config.get("output", {}).get("severity_order", ["critical", "high", "medium", "low", "info"])
    top_n = config.get("output", {}).get("console_top_findings", 15)

    safe_print("=" * 70)
    safe_print("SOC2 SCAN RESULTS")
    safe_print("=" * 70)

    for provider in PROVIDER_ORDER:
        if provider not in results:
            continue
        snap = results[provider]["snapshot"]
        diff = results[provider]["diff"]

        safe_print(f"\n--- {PROVIDER_LABELS[provider]} ---")
        safe_print(f"status: {snap['status']}")
        for err in snap.get("errors", []):
            safe_print(f"  [skipped check] {err['check']}: {err['reason']} - {err.get('detail', '')}")

        if snap["status"] == "skipped":
            continue

        if provider == "gcp":
            label_fn = lambda r: f"{r['type']} {r['id']}"  # noqa: E731
            if diff.get("baseline"):
                safe_print("  (baseline run - no prior snapshot to compare against)")
            else:
                total_changes = len(diff["added"]) + len(diff["removed"]) + len(diff["modified"])
                if total_changes == 0:
                    safe_print("  no changes since last scan")
                else:
                    safe_print(
                        f"  changes since last scan: +{len(diff['added'])} added, "
                        f"-{len(diff['removed'])} removed, {len(diff['modified'])} modified"
                    )
                    for r in _sorted_by_severity(diff["added"], order)[:top_n]:
                        safe_print(f"    [ADDED] ({r.get('severity', 'info')}) {label_fn(r)}")
                    for r in diff["removed"][:top_n]:
                        safe_print(f"    [REMOVED] {label_fn(r)}")
                    for r in _sorted_by_severity(diff["modified"], order)[:top_n]:
                        changes_str = ", ".join(
                            f"{f}: {c['before']!r} -> {c['after']!r}" for f, c in r["field_changes"].items()
                        )
                        safe_print(f"    [MODIFIED] ({r.get('severity', 'info')}) {label_fn(r)} :: {changes_str}")

            safe_print("  Manual review required (no API access to list these in GCP):")
            for url in config.get("gcp", {}).get("manual_review_urls", GCP_MANUAL_REVIEW_URLS_DEFAULT):
                safe_print(f"    - {url}")
            _render_chapters_console(_gcp_chapters(snap.get("resources", []), config), order, top_n)
            continue

        if provider == "trello":
            _board_names = {
                b["attributes"].get("board_id"): b["attributes"].get("name")
                for b in snap.get("resources", []) if b["type"] == "trello.board"
            }
            label_fn = lambda r: _trello_diff_label(r, _board_names)  # noqa: E731
        else:
            label_fn = lambda r: f"{r['type']} {r['id']}"  # noqa: E731

        if diff.get("baseline"):
            safe_print("  (baseline run - no prior snapshot to compare against)")
        else:
            total_changes = len(diff["added"]) + len(diff["removed"]) + len(diff["modified"])
            if total_changes == 0:
                safe_print("  no changes since last scan")
            else:
                safe_print(
                    f"  changes since last scan: +{len(diff['added'])} added, "
                    f"-{len(diff['removed'])} removed, {len(diff['modified'])} modified"
                )
                for r in _sorted_by_severity(diff["added"], order)[:top_n]:
                    safe_print(f"    [ADDED] ({r.get('severity', 'info')}) {label_fn(r)}")
                for r in diff["removed"][:top_n]:
                    safe_print(f"    [REMOVED] {label_fn(r)}")
                for r in _sorted_by_severity(diff["modified"], order)[:top_n]:
                    changes_str = ", ".join(
                        f"{f}: {c['before']!r} -> {c['after']!r}" for f, c in r["field_changes"].items()
                    )
                    safe_print(f"    [MODIFIED] ({r.get('severity', 'info')}) {label_fn(r)} :: {changes_str}")

        if provider == "bitbucket":
            _render_chapters_console(_bitbucket_chapters(snap.get("resources", [])), order, top_n)
            safe_print("  Manual review required (no API access to list these in Bitbucket):")
            for url in config.get("bitbucket", {}).get("manual_review_urls", BITBUCKET_MANUAL_REVIEW_URLS_DEFAULT):
                safe_print(f"    - {url}")
            continue

        if provider == "trello":
            _render_chapters_console(_trello_chapters(snap.get("resources", [])), order, top_n)
            continue

        if provider == "aws":
            _render_chapters_console(_aws_chapters(snap.get("resources", [])), order, top_n)
            continue

        if provider == "gsuite":
            _render_chapters_console(_gsuite_chapters(snap.get("resources", [])), order, top_n)
            continue

        if provider == "confluence":
            _render_chapters_console(_confluence_chapters(snap.get("resources", [])), order, top_n)
            continue

        resources = _sorted_by_severity(snap.get("resources", []), order)
        safe_print(f"  current findings (top {top_n} of {len(resources)}):")
        for r in resources[:top_n]:
            safe_print(f"    ({r.get('severity', 'info')}) {r['type']} {r['id']}")
        if len(resources) > top_n:
            safe_print(f"    ... +{len(resources) - top_n} more, see full report")

    safe_print("\n" + "=" * 70)


_HEADING_RE = re.compile(r"^(#{2,3})\s+(.*)$")


def _slugify_heading(text):
    """Approximates GitHub/VS Code's heading-anchor algorithm: lowercase,
    strip anything that isn't a word character/space/hyphen, then collapse
    each whitespace run to a single hyphen (consecutive hyphens from
    adjacent punctuation are preserved, matching real heading anchors)."""
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s+", "-", slug.strip())


def _build_toc(body_lines):
    """A table of contents is only worth it because this report can run to
    thousands of lines (dozens of SCC resource-group sub-sections alone) -
    one link per ##/### heading, indented by level. Repeated headings
    (every provider's own "Manual review required") get GitHub's "-1"/"-2"
    suffix so the links stay unique and correct."""
    toc = []
    seen = {}
    for line in body_lines:
        m = _HEADING_RE.match(line)
        if not m:
            continue
        level, text = m.groups()
        slug = _slugify_heading(text)
        seen[slug] = seen.get(slug, -1) + 1
        if seen[slug] > 0:
            slug = f"{slug}-{seen[slug]}"
        indent = "  " * (len(level) - 2)
        toc.append(f"{indent}- [{text}](#{slug})")
    return toc


def render_markdown(results, config, scope, run_id, generated_at, snapshot_paths=None):
    order = config.get("output", {}).get("severity_order", ["critical", "high", "medium", "low", "info"])
    snapshot_paths = snapshot_paths or {}
    lines = [f"# SOC2 Scan Report — scope: `{scope}`", ""]
    lines.append(f"- Run ID: `{run_id}`")
    lines.append(f"- Generated: {generated_at}")
    lines.append("")

    severity_counts = {s: 0 for s in order}
    for r in results.values():
        for res in r["snapshot"].get("resources", []):
            sev = res.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in order:
        lines.append(f"| {_fmt_severity_md(sev)} | {severity_counts.get(sev, 0)} |")
    lines.append("")

    for provider in PROVIDER_ORDER:
        if provider not in results:
            continue
        snap = results[provider]["snapshot"]
        diff = results[provider]["diff"]

        lines.append(f"## {PROVIDER_LABELS[provider]}")
        lines.append("")
        lines.append(f"**Status:** {snap['status']}")
        lines.append("")

        if snap.get("errors"):
            lines.append("**Skipped/errored checks:**")
            lines.append("")
            for err in snap["errors"]:
                lines.append(f"- `{err['check']}`: {err['reason']} — {err.get('detail', '')}")
            lines.append("")

        if snap["status"] == "skipped":
            continue

        if provider == "gcp":
            label_fn = lambda r: r["id"]  # noqa: E731
            lines.append("### Changes since last scan")
            lines.append("")
            if diff.get("baseline"):
                lines.append("_Baseline run — no prior snapshot to compare against._")
            elif not (diff["added"] or diff["removed"] or diff["modified"]):
                lines.append("_No changes._")
            else:
                lines.append("| Change | Severity | Type | ID | Details |")
                lines.append("|---|---|---|---|---|")
                for r in _sorted_by_severity(diff["added"], order):
                    lines.append(f"| added | {_fmt_severity_md(r.get('severity', 'info'))} | {r['type']} | {label_fn(r)} | |")
                for r in diff["removed"]:
                    lines.append(f"| removed | {_fmt_severity_md(r.get('severity', 'info'))} | {r['type']} | {label_fn(r)} | |")
                for r in _sorted_by_severity(diff["modified"], order):
                    details = "; ".join(
                        f"{f}: {c['before']!r} → {c['after']!r}" for f, c in r["field_changes"].items()
                    )
                    lines.append(f"| modified | {_fmt_severity_md(r.get('severity', 'info'))} | {r['type']} | {label_fn(r)} | {details} |")
            lines.append("")

            lines.append("### Manual review required")
            lines.append("")
            lines.append(
                "OAuth 2.0 Client IDs (APIs & Services > Credentials) have no public API to list "
                "them at all - this scanner can't cover them. Review this page by hand:"
            )
            lines.append("")
            for url in config.get("gcp", {}).get("manual_review_urls", GCP_MANUAL_REVIEW_URLS_DEFAULT):
                lines.append(f"- {url}")
            lines.append("")
            _render_chapters_markdown(lines, _gcp_chapters(snap.get("resources", []), config), order)
        else:
            if provider == "trello":
                _board_names = {
                    b["attributes"].get("board_id"): b["attributes"].get("name")
                    for b in snap.get("resources", []) if b["type"] == "trello.board"
                }
                label_fn = lambda r: _trello_diff_label(r, _board_names)  # noqa: E731
                id_header = "Name"
            else:
                label_fn = lambda r: r["id"]  # noqa: E731
                id_header = "ID"

            lines.append("### Changes since last scan")
            lines.append("")
            if diff.get("baseline"):
                lines.append("_Baseline run — no prior snapshot to compare against._")
            elif not (diff["added"] or diff["removed"] or diff["modified"]):
                lines.append("_No changes._")
            else:
                lines.append(f"| Change | Severity | Type | {id_header} | Details |")
                lines.append("|---|---|---|---|---|")
                for r in _sorted_by_severity(diff["added"], order):
                    lines.append(f"| added | {_fmt_severity_md(r.get('severity', 'info'))} | {r['type']} | {label_fn(r)} | |")
                for r in diff["removed"]:
                    lines.append(f"| removed | {_fmt_severity_md(r.get('severity', 'info'))} | {r['type']} | {label_fn(r)} | |")
                for r in _sorted_by_severity(diff["modified"], order):
                    details = "; ".join(
                        f"{f}: {c['before']!r} → {c['after']!r}" for f, c in r["field_changes"].items()
                    )
                    lines.append(f"| modified | {_fmt_severity_md(r.get('severity', 'info'))} | {r['type']} | {label_fn(r)} | {details} |")
            lines.append("")

            if provider == "bitbucket":
                _render_chapters_markdown(lines, _bitbucket_chapters(snap.get("resources", [])), order)
                lines.append("### Manual review required")
                lines.append("")
                lines.append(
                    "Bitbucket's public API has no way to list Access Tokens at any scope, and "
                    "gates Deploy Keys / Branch Restrictions / Project Access Keys behind admin-level "
                    "scopes this scanner isn't configured to hold. Review these pages by hand:"
                )
                lines.append("")
                for url in config.get("bitbucket", {}).get("manual_review_urls", BITBUCKET_MANUAL_REVIEW_URLS_DEFAULT):
                    lines.append(f"- {url}")
                lines.append("")
            elif provider == "aws":
                _render_chapters_markdown(lines, _aws_chapters(snap.get("resources", [])), order)
            elif provider == "trello":
                _render_chapters_markdown(lines, _trello_chapters(snap.get("resources", [])), order)
            elif provider == "gsuite":
                _render_chapters_markdown(lines, _gsuite_chapters(snap.get("resources", [])), order)
            elif provider == "confluence":
                _render_chapters_markdown(lines, _confluence_chapters(snap.get("resources", [])), order)
            else:
                resources = _sorted_by_severity(snap.get("resources", []), order)
                lines.append(f"### Current findings ({len(resources)} total)")
                lines.append("")
                if resources:
                    lines.append("| Severity | Type | ID | Tags |")
                    lines.append("|---|---|---|---|")
                    for r in resources:
                        tags = ", ".join(r.get("tags", []))
                        lines.append(f"| {_fmt_severity_md(r.get('severity', 'info'))} | {r['type']} | {r['id']} | {tags} |")
                else:
                    lines.append("_No resources found._")
                lines.append("")

        counts_by_type = {}
        for r in snap.get("resources", []):
            counts_by_type[r["type"]] = counts_by_type.get(r["type"], 0) + 1
        lines.append("<details><summary>Resource counts by type</summary>")
        lines.append("")
        for t, c in sorted(counts_by_type.items()):
            lines.append(f"- `{t}`: {c}")
        if provider in snapshot_paths:
            lines.append("")
            lines.append(f"Full JSON snapshot: `{snapshot_paths[provider]}`")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    header_end = 5  # title, blank, run ID, generated, blank - see the top of this function
    toc = ["## Table of Contents", ""] + _build_toc(lines[header_end:]) + [""]
    lines = lines[:header_end] + toc + lines[header_end:]

    return "\n".join(lines) + "\n"
