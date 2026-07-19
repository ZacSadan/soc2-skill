"""Google Workspace (G Suite) provider scanner: user directory security
posture via domain-wide delegation - suspended/active status, 2FA
enrollment/enforcement, admin privilege, dormant-but-active-account
detection, group memberships, org unit structure, mobile device posture,
and audit-log-derived suspicious login / OAuth app grant activity.

Reuses the same GCP service-account key already used by gcp_scanner.py,
scoped down to a curated set of *.readonly Admin SDK scopes and
impersonating a delegated admin user via domain-wide delegation - a
materially different, domain-wide trust model than the project-scoped GCP
IAM roles used elsewhere in this scanner (see references/gsuite_setup.md).
Missing delegation config is a first-class expected state (this has to be
set up manually by a Workspace Super Admin) - the scanner no-ops with a
clear message rather than raising.

Every check is independently try/excepted so one failing check never aborts
the rest of the scan - failures are recorded in `errors` with a reason
string instead, same resilience pattern as every other provider here.
"""
import datetime
import os

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from common.redact import register_secret

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
]

RECOMMENDED_MAX_SUPER_ADMINS = 4

# Deliberately excludes plain "login_failure" / "login_success" - those are
# routine (typos happen) and would flood the report; these are the event
# names Google's own login activity log reserves for genuinely concerning
# signals. Severity reflects how unambiguous a bad signal each one is.
CONCERNING_LOGIN_EVENTS = {
    "suspicious_login": "high",
    "suspicious_login_less_secure_app": "high",
    "suspicious_programmatic_login": "high",
    "account_disabled_password_leak": "critical",
    "account_disabled_spamming": "high",
    "account_disabled_generic": "medium",
}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _age_days(iso_ts):
    if not iso_ts:
        return None
    try:
        dt = datetime.datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return (_now() - dt).days
    except ValueError:
        return None


def _http_error_reason(e):
    status = getattr(getattr(e, "resp", None), "status", None)
    if status == 403:
        return "PERMISSION_DENIED"
    if status == 404:
        return "NOT_FOUND"
    return f"HTTP_{status}" if status else "ERROR"


def scan_users(directory, stale_login_days, errors):
    """Lists every user in the Workspace directory and flags: admins
    without enforced 2FA (critical - a compromised admin account is
    catastrophic), any active user with no 2FA at all (high), and active
    accounts that haven't logged in for a long time (medium - often a
    departed employee whose account was never suspended)."""
    resources = []
    try:
        users = []
        page_token = None
        while True:
            kwargs = {"customer": "my_customer", "maxResults": 500, "orderBy": "email"}
            if page_token:
                kwargs["pageToken"] = page_token
            resp = directory.users().list(**kwargs).execute()
            users.extend(resp.get("users", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
    except HttpError as e:
        errors.append({"check": "gsuite_users", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for u in users:
        email = u.get("primaryEmail")
        suspended = bool(u.get("suspended"))
        archived = bool(u.get("archived"))
        is_admin = bool(u.get("isAdmin"))
        is_delegated_admin = bool(u.get("isDelegatedAdmin"))
        is_enrolled_2sv = bool(u.get("isEnrolledIn2Sv"))
        is_enforced_2sv = bool(u.get("isEnforcedIn2Sv"))
        last_login = u.get("lastLoginTime")
        login_age = _age_days(last_login)
        is_privileged = is_admin or is_delegated_admin

        severity = "info"
        tags = ["gsuite", "user"]
        if not suspended and is_privileged and not is_enforced_2sv:
            severity = "critical"
            tags.append("admin_no_2fa_enforced")
        elif not suspended and not is_enrolled_2sv:
            severity = "high"
            tags.append("no_2fa")
        elif not suspended and login_age is not None and login_age > stale_login_days:
            severity = "medium"
            tags.append("dormant_active_account")
        elif suspended:
            tags.append("suspended")

        resources.append({
            "type": "gsuite.user",
            "id": f"gsuite_user:{email}",
            "attributes": {
                "email": email,
                "full_name": (u.get("name") or {}).get("fullName"),
                "suspended": suspended,
                "archived": archived,
                "is_admin": is_admin,
                "is_delegated_admin": is_delegated_admin,
                "is_enrolled_2sv": is_enrolled_2sv,
                "is_enforced_2sv": is_enforced_2sv,
                "last_login": last_login,
                "login_age_days": login_age,
                "org_unit_path": u.get("orgUnitPath"),
            },
            "severity": severity,
            "tags": tags,
        })

    return resources


def scan_admin_summary(user_resources):
    """Derived from the already-fetched user list (no extra API call) -
    Google/Prowler's own guidance recommends 2-4 super admins: enough for
    resilience if one is unavailable, not so many that admin privilege is
    sprawled across the org."""
    active = [r for r in user_resources if not r["attributes"]["suspended"]]
    active_admins = [r for r in active if r["attributes"]["is_admin"] or r["attributes"]["is_delegated_admin"]]
    super_admins = [r for r in active_admins if r["attributes"]["is_admin"]]
    count = len(super_admins)

    severity = "info"
    tags = ["gsuite", "admin_summary"]
    if count == 0:
        severity = "critical"
        tags.append("no_super_admins")
    elif count == 1:
        severity = "medium"
        tags.append("single_super_admin")
    elif count > RECOMMENDED_MAX_SUPER_ADMINS:
        severity = "low"
        tags.append("excess_super_admins")

    return [{
        "type": "gsuite.admin_summary",
        "id": "gsuite_admin_summary",
        "attributes": {
            "super_admin_count": count,
            "super_admin_emails": sorted(r["attributes"]["email"] for r in super_admins),
            "delegated_admin_count": len(active_admins) - count,
        },
        "severity": severity,
        "tags": tags,
    }]


def scan_groups(directory, errors):
    """Lists every group and its direct members, flagging OWNER/MANAGER
    roles as the group-level equivalent of admin privilege - these
    determine who can add/remove members and change group settings, not
    just who's in the group. Purely an inventory/context chapter otherwise
    (severity info) - which group names are "privileged" isn't something
    that can be judged reliably from data alone."""
    resources = []
    try:
        groups = []
        page_token = None
        while True:
            kwargs = {"customer": "my_customer", "maxResults": 200}
            if page_token:
                kwargs["pageToken"] = page_token
            resp = directory.groups().list(**kwargs).execute()
            groups.extend(resp.get("groups", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
    except HttpError as e:
        errors.append({"check": "gsuite_groups", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for g in groups:
        email = g.get("email")
        owners, managers, member_count = [], [], 0
        try:
            members = []
            page_token = None
            while True:
                kwargs = {"groupKey": email, "maxResults": 200}
                if page_token:
                    kwargs["pageToken"] = page_token
                resp = directory.members().list(**kwargs).execute()
                members.extend(resp.get("members", []))
                page_token = resp.get("nextPageToken")
                if not page_token:
                    break
            member_count = len(members)
            owners = sorted(m.get("email") for m in members if m.get("role") == "OWNER" and m.get("email"))
            managers = sorted(m.get("email") for m in members if m.get("role") == "MANAGER" and m.get("email"))
        except HttpError as e:
            errors.append({"check": f"gsuite_group_members:{email}", "reason": _http_error_reason(e), "detail": str(e)})

        resources.append({
            "type": "gsuite.group",
            "id": f"gsuite_group:{email}",
            "attributes": {
                "email": email,
                "name": g.get("name"),
                "description": g.get("description"),
                "direct_members_count": member_count,
                "owners": owners,
                "managers": managers,
            },
            "severity": "info",
            "tags": ["gsuite", "group"],
        })

    return resources


def scan_org_units(directory, errors):
    """Lists the org unit hierarchy - purely structural/inventory context
    for interpreting each user's org_unit_path, not a findings chapter on
    its own."""
    resources = []
    try:
        resp = directory.orgunits().list(customerId="my_customer", type="all").execute()
        org_units = resp.get("organizationUnits", [])
    except HttpError as e:
        errors.append({"check": "gsuite_org_units", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for ou in org_units:
        path = ou.get("orgUnitPath")
        resources.append({
            "type": "gsuite.org_unit",
            "id": f"gsuite_org_unit:{path}",
            "attributes": {
                "name": ou.get("name"),
                "description": ou.get("description"),
                "org_unit_path": path,
                "parent_org_unit_path": ou.get("parentOrgUnitPath"),
                "block_inheritance": bool(ou.get("blockInheritance")),
            },
            "severity": "info",
            "tags": ["gsuite", "org_unit"],
        })

    return resources


def scan_mobile_devices(directory, errors):
    """Lists mobile devices with directory/data access and flags real
    posture problems: a device flagged compromised (critical - rooted/
    jailbroken or known-bad), an approved-and-active device with no disk
    encryption (high - lost/stolen device fully readable), and no
    screen-lock password set (medium)."""
    resources = []
    try:
        devices = []
        page_token = None
        while True:
            kwargs = {"customerId": "my_customer", "maxResults": 100}
            if page_token:
                kwargs["pageToken"] = page_token
            resp = directory.mobiledevices().list(**kwargs).execute()
            devices.extend(resp.get("mobiledevices", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
    except HttpError as e:
        errors.append({"check": "gsuite_mobile_devices", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for d in devices:
        device_id = d.get("deviceId")
        status = d.get("status")
        is_active = status == "APPROVED"
        compromised_status = d.get("deviceCompromisedStatus", "")
        encryption_status = d.get("encryptionStatus", "")
        password_status = d.get("devicePasswordStatus", "")
        # Exact match, not a substring check - confirmed live that the safe
        # values include both "Undetected" (Android) and "No compromise
        # detected" (iOS), and the latter contains the substring "compromis"
        # despite meaning the opposite - a substring match on "compromis"
        # alone produced false-positive criticals on every iOS device.
        # Google's Admin SDK docs don't publish a definitive enum list for
        # this field, so this only fires on the one literal value observed
        # to actually mean "compromised".
        is_compromised = compromised_status.strip().lower() == "compromised"

        severity = "info"
        tags = ["gsuite", "mobile_device"]
        if is_active and is_compromised:
            severity = "critical"
            tags.append("compromised")
        elif is_active and encryption_status and encryption_status.lower() not in ("encrypted",):
            severity = "high"
            tags.append("unencrypted")
        elif is_active and password_status and password_status.lower() not in ("on",):
            severity = "medium"
            tags.append("no_password")

        resources.append({
            "type": "gsuite.mobile_device",
            "id": f"gsuite_mobile_device:{device_id}",
            "attributes": {
                "device_id": device_id,
                "owner_email": (d.get("email") or [None])[0],
                "model": d.get("model"),
                "os": d.get("os"),
                "type": d.get("type"),
                "status": status,
                "compromised_status": compromised_status,
                "encryption_status": encryption_status,
                "password_status": password_status,
                "last_sync": d.get("lastSync"),
                "last_sync_age_days": _age_days(d.get("lastSync")),
            },
            "severity": severity,
            "tags": tags,
        })

    return resources


def scan_suspicious_logins(reports_svc, lookback_days, errors):
    """Reports API login activity, filtered to a curated set of genuinely
    concerning event names (see CONCERNING_LOGIN_EVENTS) - not plain
    login_failure/login_success, which are routine and would flood the
    report. One activities().list call per event name (bounded to
    lookback_days) rather than fetching all login events and filtering
    client-side, since successful/failed logins vastly outnumber
    suspicious ones in a normal org."""
    resources = []
    start_time = _iso(_now() - datetime.timedelta(days=lookback_days))

    for event_name, severity in CONCERNING_LOGIN_EVENTS.items():
        try:
            items = []
            page_token = None
            while True:
                kwargs = {
                    "userKey": "all", "applicationName": "login", "eventName": event_name,
                    "startTime": start_time, "maxResults": 200,
                }
                if page_token:
                    kwargs["pageToken"] = page_token
                resp = reports_svc.activities().list(**kwargs).execute()
                items.extend(resp.get("items", []))
                page_token = resp.get("nextPageToken")
                if not page_token or len(items) >= 500:  # bounded - this is a signal list, not a full audit export
                    break
        except HttpError as e:
            errors.append({"check": f"gsuite_login_activity:{event_name}", "reason": _http_error_reason(e), "detail": str(e)})
            continue

        for item in items:
            event_id = item.get("id", {})
            actor_email = (item.get("actor") or {}).get("email")
            time_str = event_id.get("time")
            unique_qualifier = event_id.get("uniqueQualifier", "")
            resources.append({
                "type": "gsuite.login_event",
                "id": f"gsuite_login_event:{event_name}:{unique_qualifier}",
                "attributes": {
                    "event_name": event_name,
                    "actor_email": actor_email,
                    "time": time_str,
                    "ip_address": item.get("ipAddress"),
                    "region_code": (item.get("networkInfo") or {}).get("regionCode"),
                },
                "severity": severity,
                "tags": ["gsuite", "login_event", event_name],
            })

    return resources


def scan_oauth_app_grants(reports_svc, lookback_days, errors):
    """Reports API token activity, filtered to "authorize" events - which
    third-party/internal apps were granted OAuth access to Workspace data,
    by whom, and with what scopes, within the lookback window. This is the
    read-only path to OAuth-grant visibility: the alternative,
    admin.directory.user.security, also grants the ability to turn off a
    user's 2FA (confirmed against Google's own reference docs) and was
    deliberately not requested for that reason."""
    resources = []
    start_time = _iso(_now() - datetime.timedelta(days=lookback_days))

    try:
        items = []
        page_token = None
        while True:
            kwargs = {
                "userKey": "all", "applicationName": "token", "eventName": "authorize",
                "startTime": start_time, "maxResults": 200,
            }
            if page_token:
                kwargs["pageToken"] = page_token
            resp = reports_svc.activities().list(**kwargs).execute()
            items.extend(resp.get("items", []))
            page_token = resp.get("nextPageToken")
            if not page_token or len(items) >= 500:
                break
    except HttpError as e:
        errors.append({"check": "gsuite_oauth_grants", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for item in items:
        event_id = item.get("id", {})
        actor_email = (item.get("actor") or {}).get("email")
        unique_qualifier = event_id.get("uniqueQualifier", "")
        for event in item.get("events", []):
            params = {p.get("name"): p for p in event.get("parameters", [])}
            client_id = (params.get("client_id") or {}).get("value")
            app_name = (params.get("app_name") or {}).get("value") or client_id
            scopes = []
            scope_data = (params.get("scope_data") or {}).get("multiMessageValue", [])
            for entry in scope_data:
                for p in entry.get("parameter", []):
                    if p.get("name") == "scope_name":
                        scopes.append(p.get("value"))

            is_broad_grant = any("admin.directory" in s and not s.endswith(".readonly") for s in scopes)

            resources.append({
                "type": "gsuite.oauth_grant",
                "id": f"gsuite_oauth_grant:{client_id}:{actor_email}:{unique_qualifier}",
                "attributes": {
                    "app_name": app_name,
                    "client_id": client_id,
                    "actor_email": actor_email,
                    "time": event_id.get("time"),
                    "scopes": sorted(scopes),
                },
                "severity": "medium" if is_broad_grant else "info",
                "tags": ["gsuite", "oauth_grant"] + (["broad_admin_scope"] if is_broad_grant else []),
            })

    return resources


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def scan(config, errors):
    """Returns (resources, status, message). message is only set for the
    'skipped' status."""
    gsuite_cfg = config.get("gsuite", {})
    key_path = gsuite_cfg.get("_key_path_resolved")
    admin_path = gsuite_cfg.get("_delegated_admin_path_resolved")

    # delegated_admin_email is a literal fallback (typically set in
    # secrets/soc2.config.private.yaml, itself gitignored) - a gitignored
    # secrets/ file at admin_path takes precedence if present, same
    # precedence pattern as bitbucket.account_email.
    delegated_user = gsuite_cfg.get("delegated_admin_email")
    if admin_path and os.path.exists(admin_path):
        with open(admin_path, "r", encoding="utf-8") as f:
            delegated_user = f.read().strip()
        # Deliberately NOT registered as a secret: this is a real employee's
        # email that legitimately appears throughout the Workspace data itself
        # (Users list, group owners, OAuth grant actors, admin summary, login
        # events) - registering it would redact all of those too, not just its
        # use as the impersonation subject. Knowing this address grants no
        # capability by itself anyway; the actual credential is the service
        # account's private key file, registered below.

    if not delegated_user:
        message = (
            "Delegated admin email not configured (gsuite.delegated_admin_email or "
            f"a file at {admin_path}) - skipping. "
            "See references/gsuite_setup.md for how to set up domain-wide delegation."
        )
        return [], "skipped", message

    if not key_path or not os.path.exists(key_path):
        errors.append({"check": "gsuite_auth", "reason": "MISSING_CREDENTIALS", "detail": f"No key file at {key_path}"})
        return [], "error", None

    with open(key_path, "r", encoding="utf-8") as f:
        register_secret(f.read())

    try:
        creds = service_account.Credentials.from_service_account_file(key_path, scopes=SCOPES).with_subject(delegated_user)
        directory = build("admin", "directory_v1", credentials=creds)
        reports_svc = build("admin", "reports_v1", credentials=creds)
    except Exception as e:  # noqa: BLE001
        errors.append({"check": "gsuite_auth", "reason": "ERROR", "detail": str(e)})
        return [], "error", None

    checks_cfg = gsuite_cfg.get("checks", {})
    audit_lookback_days = gsuite_cfg.get("audit_lookback_days", 30)
    resources = []

    user_resources = []
    if checks_cfg.get("users", True):
        user_resources = scan_users(directory, gsuite_cfg.get("stale_login_days", 180), errors)
        resources += user_resources

    if checks_cfg.get("admin_summary", True) and user_resources:
        resources += scan_admin_summary(user_resources)

    if checks_cfg.get("groups", True):
        resources += scan_groups(directory, errors)
    if checks_cfg.get("org_units", True):
        resources += scan_org_units(directory, errors)
    if checks_cfg.get("mobile_devices", True):
        resources += scan_mobile_devices(directory, errors)
    if checks_cfg.get("suspicious_logins", True):
        resources += scan_suspicious_logins(reports_svc, audit_lookback_days, errors)
    if checks_cfg.get("oauth_app_grants", True):
        resources += scan_oauth_app_grants(reports_svc, audit_lookback_days, errors)

    status = "ok" if not errors else "partial"
    return resources, status, None
