"""Confluence provider scanner: spaces and per-space permissions, with a
focus on anonymous/public access exposure and space administration - the
Confluence analog of the "public bucket"/"public repo" checks in the other
providers.

Uses the same Atlassian Basic-auth (email + API token) mechanism as the
Bitbucket scanner, reusing the shared delegated-admin identity (set inline
in secrets/soc2.config.private.yaml) for the account email. Requests are
routed through Atlassian's
centralized API gateway (api.atlassian.com/ex/confluence/{cloud_id}/...)
rather than the site's own domain directly - confirmed live that this
site's own domain (fronted by an SSO-enforcement proxy on its legacy
.jira.com hostname) rejects direct API requests with a raw, non-JSON 401,
while the same Basic-auth credentials work cleanly through the gateway.
See references/confluence_setup.md for how this was discovered.

Every check is independently try/excepted so one failing check never
aborts the rest of the scan - failures are recorded in `errors` with a
reason string instead, same resilience pattern as every other provider.
"""
import os

import requests

from common.redact import register_secret

GATEWAY_BASE = "https://api.atlassian.com/ex/confluence"

# Operations that amount to being able to administer a space - the
# Confluence analog of "who's an owner/admin" checks elsewhere.
# Confirmed live against a real space's permission list - the actual
# operation name is "administer" (targetType "space"), not "admin" or
# "setspacepermissions" (an initial guess that matched nothing at all,
# silently producing zero admins across all 1533 spaces until caught).
ADMIN_OPERATIONS = {"administer"}


def _has_admin_op(ops):
    """ops is a set of "operation:targetType" strings (e.g. "create:page",
    "administer:space") - checks the operation half against ADMIN_OPERATIONS
    since target type doesn't affect whether a grant is admin-equivalent."""
    return any(o.split(":", 1)[0] in ADMIN_OPERATIONS for o in ops)


def _load_token(token_path):
    with open(token_path, "r", encoding="utf-8") as f:
        token = f.read().strip()
    register_secret(token)
    return token


def _reason(e):
    resp = getattr(e, "response", None)
    if resp is not None:
        return f"HTTP_{resp.status_code}"
    return "ERROR"


def _list_all_space_summaries(session, base, errors):
    """Paginates the plain space list (no permissions expand) - cheap enough
    to run in full even across 1500+ spaces, used both by the full-listing
    fallback and to count "other" spaces when main_space is configured."""
    spaces = []
    try:
        url = f"{base}/wiki/rest/api/space"
        params = {"limit": 100}
        while url:
            resp = session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            spaces.extend(data.get("results", []))
            next_path = (data.get("_links") or {}).get("next")
            url = f"{base}/wiki{next_path}" if next_path else None
            params = None
    except requests.RequestException as e:
        errors.append({"check": "confluence_spaces", "reason": _reason(e), "detail": str(e)})
    return spaces


def _fetch_space_detail(session, base, key, errors):
    """Fetches one space with its permissions expanded. Returns
    (anonymous_operations, admins, user_ops, group_ops) - the last two map
    display name -> set of "operation:targetType" strings (e.g. "create:page",
    "create:comment", "delete:attachment") for the "all users and their
    permissions" view. Kept as the full pair rather than collapsing to just
    the operation name - Confluence grants "create"/"delete" separately per
    content type (page, comment, attachment, blogpost, space), and folding
    those into one bucket silently lost exactly which of those a subject
    actually holds."""
    anonymous_operations = []
    admins = []
    user_ops = {}
    group_ops = {}
    try:
        resp = session.get(f"{base}/wiki/rest/api/space/{key}", params={"expand": "permissions"}, timeout=30)
        resp.raise_for_status()
        for p in resp.json().get("permissions", []):
            op_info = p.get("operation") or {}
            op, target = op_info.get("operation"), op_info.get("targetType")
            op_key = f"{op}:{target}"
            if p.get("anonymousAccess"):
                anonymous_operations.append(op_key)
            subjects = p.get("subjects") or {}
            for u in (subjects.get("user") or {}).get("results", []):
                name = u.get("displayName") or u.get("publicName") or u.get("accountId")
                user_ops.setdefault(name, set()).add(op_key)
                if op in ADMIN_OPERATIONS:
                    admins.append(name)
            for g in (subjects.get("group") or {}).get("results", []):
                name = f"group:{g.get('name')}"
                group_ops.setdefault(name, set()).add(op_key)
                if op in ADMIN_OPERATIONS:
                    admins.append(name)
    except requests.RequestException as e:
        errors.append({"check": f"confluence_space_permissions:{key}", "reason": _reason(e), "detail": str(e)})
    return anonymous_operations, admins, user_ops, group_ops


def _list_all_groups(session, base, errors):
    """Paginates the site's group directory (name + id) - the id is needed
    for membersByGroupId since space permissions only expose group names."""
    groups = []
    try:
        url = f"{base}/wiki/rest/api/group"
        params = {"limit": 200}
        while url:
            resp = session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            groups.extend(data.get("results", []))
            next_path = (data.get("_links") or {}).get("next")
            url = f"{base}/wiki{next_path}" if next_path else None
            params = None
    except requests.RequestException as e:
        errors.append({"check": "confluence_groups", "reason": _reason(e), "detail": str(e)})
    return groups


def _group_members(session, base, group_id, group_name, errors):
    """Paginates a group's real members via membersByGroupId - the by-name
    /group/{name}/member endpoint 401s ("scope does not match") under this
    token's granted scopes, confirmed live; membersByGroupId works fine."""
    members = []
    try:
        url = f"{base}/wiki/rest/api/group/{group_id}/membersByGroupId"
        params = {"limit": 200}
        while url:
            resp = session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            members.extend(data.get("results", []))
            next_path = (data.get("_links") or {}).get("next")
            url = f"{base}/wiki{next_path}" if next_path else None
            params = None
    except requests.RequestException as e:
        errors.append({"check": f"confluence_group_members:{group_name}", "reason": _reason(e), "detail": str(e)})
    return members


def _resolve_group_grants(session, base, group_ops, errors):
    """Expands each group's operation grants onto its actual member users,
    so the main-space permission report shows every real person who can
    reach the space (directly or via group membership), not an opaque
    "group:administrators" placeholder. Returns (resolved_user_ops,
    unresolved_group_names) - a group is "unresolved" if its id can't be
    found in the site's group directory or its member list fails to load,
    in which case its opaque group grant is kept instead of being dropped
    silently."""
    resolved_user_ops = {}
    unresolved = []
    if not group_ops:
        return resolved_user_ops, unresolved

    groups = _list_all_groups(session, base, errors)
    name_to_id = {g.get("name"): g.get("id") for g in groups}

    for group_key, ops in group_ops.items():
        raw_name = group_key[len("group:"):] if group_key.startswith("group:") else group_key
        group_id = name_to_id.get(raw_name)
        if not group_id:
            unresolved.append(group_key)
            continue
        members = _group_members(session, base, group_id, raw_name, errors)
        if not members:
            unresolved.append(group_key)
            continue
        for m in members:
            name = m.get("displayName") or m.get("publicName") or m.get("accountId")
            resolved_user_ops.setdefault(name, {"ops": set(), "via": set()})
            resolved_user_ops[name]["ops"] |= ops
            resolved_user_ops[name]["via"].add(f"group:{raw_name}")

    return resolved_user_ops, unresolved


def _space_resource(space, anonymous_operations, admins):
    key = space.get("key")
    is_public = bool(anonymous_operations)
    return {
        "type": "confluence.space",
        "id": f"confluence_space:{key}",
        "attributes": {
            "key": key,
            "name": space.get("name"),
            "space_type": space.get("type"),
            "status": space.get("status"),
            "anonymous_access": is_public,
            "anonymous_operations": sorted(set(anonymous_operations)),
            "admins": sorted(set(admins)),
        },
        "severity": "critical" if is_public else "info",
        "tags": ["confluence", "space"] + (["public"] if is_public else []),
    }


def scan_main_space(session, base, main_space, errors):
    """Scans only the configured main_space in full detail - every real user
    who can reach it (whether granted directly or via a group they belong
    to) and the operations they hold - and adds a single summary note
    counting whatever other spaces this account can also see, instead of
    listing them all - the 1500+-space fleet under this account is too
    large and low signal to enumerate row by row when only one space
    actually matters."""
    resources = []

    all_summaries = _list_all_space_summaries(session, base, errors)
    other_count = len([s for s in all_summaries if s.get("key") != main_space])

    space = next((s for s in all_summaries if s.get("key") == main_space), {"key": main_space})
    anonymous_operations, admins, user_ops, group_ops = _fetch_space_detail(session, base, main_space, errors)

    # Merge direct grants and group-resolved grants into one per-user view,
    # tracking where each person's access comes from ("direct" and/or a
    # specific group name) so the report stays auditable rather than just
    # flattening everyone into a single undifferentiated list.
    merged = {name: {"ops": set(ops), "via": {"direct"}} for name, ops in user_ops.items()}
    resolved_group_users, unresolved_groups = _resolve_group_grants(session, base, group_ops, errors)
    for name, info in resolved_group_users.items():
        entry = merged.setdefault(name, {"ops": set(), "via": set()})
        entry["ops"] |= info["ops"]
        entry["via"] |= info["via"]

    admins_final = sorted({name for name, info in merged.items() if _has_admin_op(info["ops"])} | set(unresolved_groups))
    resources.append(_space_resource(space, anonymous_operations, admins_final))

    for name, info in sorted(merged.items()):
        ops = info["ops"]
        resources.append({
            "type": "confluence.space_permission",
            "id": f"confluence_space_permission:{main_space}:user:{name}",
            "attributes": {
                "space_key": main_space,
                "subject": name,
                "subject_type": "user",
                "operations": sorted(ops),
                "via": sorted(info["via"]),
            },
            "severity": "high" if _has_admin_op(ops) else "info",
            "tags": ["confluence", "space_permission"] + (["admin"] if _has_admin_op(ops) else []),
        })
    for name in sorted(unresolved_groups):
        ops = group_ops.get(name, set())
        resources.append({
            "type": "confluence.space_permission",
            "id": f"confluence_space_permission:{main_space}:{name}",
            "attributes": {
                "space_key": main_space,
                "subject": name,
                "subject_type": "group",
                "operations": sorted(ops),
                "via": ["direct"],
            },
            "severity": "high" if _has_admin_op(ops) else "info",
            "tags": ["confluence", "space_permission"] + (["admin"] if _has_admin_op(ops) else []),
        })

    resources.append({
        "type": "confluence.other_spaces_summary",
        "id": f"confluence_other_spaces_summary:{main_space}",
        "attributes": {
            "main_space": main_space,
            "other_space_count": other_count,
        },
        "severity": "info",
        "tags": ["confluence", "other_spaces_summary"],
    })

    return resources


def scan_spaces(session, base, errors):
    """Lists every space and its permission grants, flagging any space with
    an anonymousAccess grant on any operation as a public-exposure finding,
    and listing who holds admin/setspacepermissions on each space. Used only
    when no main_space is configured - see scan_main_space for the focused
    alternative."""
    resources = []
    spaces = _list_all_space_summaries(session, base, errors)
    for space in spaces:
        key = space.get("key")
        anonymous_operations, admins, _user_ops, _group_ops = _fetch_space_detail(session, base, key, errors)
        resources.append(_space_resource(space, anonymous_operations, admins))
    return resources


def scan(config, errors):
    """Returns (resources, status, message). message is only set for the
    'skipped' status."""
    cfg = config.get("confluence", {})
    token_path = cfg.get("_token_path_resolved")
    email_path = cfg.get("_account_email_path_resolved")
    cloud_id = cfg.get("cloud_id")

    if not token_path or not os.path.exists(token_path):
        message = (
            f"Confluence token not configured at {token_path} - skipping. "
            "See references/confluence_setup.md."
        )
        return [], "skipped", message

    if not cloud_id:
        errors.append({
            "check": "confluence_auth", "reason": "MISSING_CLOUD_ID",
            "detail": "confluence.cloud_id not set - add it to secrets/soc2.config.private.yaml",
        })
        return [], "error", None

    # account_email is a literal fallback (typically set in
    # secrets/soc2.config.private.yaml, itself gitignored) - a gitignored
    # secrets/ file at email_path takes precedence if present, same
    # precedence pattern as bitbucket.account_email.
    email = cfg.get("account_email")
    if email_path and os.path.exists(email_path):
        with open(email_path, "r", encoding="utf-8") as f:
            email = f.read().strip()
    # email deliberately NOT registered as a secret - see the same fix
    # applied to gsuite/bitbucket: it's a real identity that can legitimately
    # appear in Confluence data itself (space admins, permission grants).

    if not email:
        errors.append({
            "check": "confluence_auth", "reason": "MISSING_ACCOUNT_EMAIL",
            "detail": f"No confluence.account_email set and no file at {email_path}",
        })
        return [], "error", None

    token = _load_token(token_path)

    session = requests.Session()
    session.auth = (email, token)
    base = f"{GATEWAY_BASE}/{cloud_id}"

    main_space = cfg.get("main_space")

    checks_cfg = cfg.get("checks", {})
    resources = []
    if checks_cfg.get("spaces", True):
        if main_space:
            resources += scan_main_space(session, base, main_space, errors)
        else:
            resources += scan_spaces(session, base, errors)

    status = "ok" if not errors else "partial"
    return resources, status, None
