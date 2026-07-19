"""GCP provider scanner: IAM service accounts/keys, IAM policy bindings,
Compute Engine firewall rules, SSH key metadata, and best-effort Security
Command Center findings / IAM Recommender.

Every check is independently try/excepted so one failing or disabled check
never aborts the rest of the scan - failures are recorded in `errors` with a
reason string instead.
"""
import base64
import datetime
import hashlib

import google.auth.transport.requests as google_auth_transport_requests
import requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from common.redact import register_secret

SCC_V2_BASE = "https://securitycenter.googleapis.com/v2"

# The .read-only scope variant rejects some IAM/Compute read methods outright
# (ACCESS_TOKEN_SCOPE_INSUFFICIENT) even when the underlying IAM role is
# read-only. OAuth scope is only a ceiling; the actual security boundary is
# the service account's IAM roles (see references/gcp_setup.md), so the full
# cloud-platform scope is used here deliberately.
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

HIGH_RISK_ROLES = {"roles/owner", "roles/editor", "roles/iam.securityAdmin"}


def _credentials(key_path):
    with open(key_path, "r", encoding="utf-8") as f:
        register_secret(f.read())
    return service_account.Credentials.from_service_account_file(key_path, scopes=SCOPES)


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
        return "SERVICE_DISABLED_OR_NOT_FOUND"
    if status == 400:
        return "NEEDS_ORG_SCOPED_PARENT"
    return f"HTTP_{status}" if status else "ERROR"


def _fingerprint(pubkey_b64):
    try:
        raw = base64.b64decode(pubkey_b64)
        return hashlib.sha256(raw).hexdigest()[:16]
    except Exception:  # noqa: BLE001 - malformed key material, not fatal
        return "unparseable"


def scan_iam_service_accounts_and_keys(creds, project_id, key_age_warn_days, key_age_critical_days, errors):
    resources = []
    try:
        iam = build("iam", "v1", credentials=creds, cache_discovery=False)
        service_accounts = []
        req = iam.projects().serviceAccounts().list(name=f"projects/{project_id}")
        while req is not None:
            resp = req.execute()
            service_accounts.extend(resp.get("accounts", []))
            req = iam.projects().serviceAccounts().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "iam_service_accounts", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for sa in service_accounts:
        email = sa["email"]

        try:
            keys = iam.projects().serviceAccounts().keys().list(
                name=f"projects/{project_id}/serviceAccounts/{email}", keyTypes="USER_MANAGED"
            ).execute().get("keys", [])
        except HttpError as e:
            errors.append({"check": f"iam_service_account_keys:{email}", "reason": _http_error_reason(e), "detail": str(e)})
            keys = None  # unknown (not zero) - key-related columns render as "unknown", not "no keys"

        resources.append({
            "type": "gcp.iam.service_account",
            "id": f"sa:{email}",
            "attributes": {
                "email": email,
                "display_name": sa.get("displayName", ""),
                "description": sa.get("description", ""),
                "disabled": sa.get("disabled", False),
                "unique_id": sa.get("uniqueId"),
                "has_keys": None if keys is None else bool(keys),
                "key_count": None if keys is None else len(keys),
            },
            "severity": "info",
            "tags": ["iam", "service_account"],
        })

        if keys is None:
            continue

        for key in keys:
            key_id = key["name"].rsplit("/", 1)[-1]
            age = _age_days(key.get("validAfterTime"))
            severity = "info"
            if age is not None:
                if age >= key_age_critical_days:
                    severity = "critical"
                elif age >= key_age_warn_days:
                    severity = "high"
            resources.append({
                "type": "gcp.iam.service_account_key",
                "id": f"sa_key:{email}:{key_id}",
                "attributes": {
                    "service_account": email,
                    "key_id": key_id,
                    "key_type": key.get("keyType", "USER_MANAGED"),
                    "valid_after": key.get("validAfterTime"),
                    "age_days": age,
                    "disabled": key.get("disabled", False),
                },
                "severity": severity,
                "tags": ["iam", "service_account_key"] + (["unrotated"] if severity in ("high", "critical") else []),
            })

    return resources


def _is_custom_role(role):
    """Predefined roles are named "roles/xxx"; custom roles are scoped to
    where they were created: "projects/{id}/roles/xxx" or
    "organizations/{id}/roles/xxx"."""
    return role.startswith("projects/") or role.startswith("organizations/")


def _role_included_permissions(iam, role, cache, errors):
    """Fetches a custom role's includedPermissions, caching per unique role
    name so a role bound to N members is only fetched once. Predefined
    roles are never expanded - even a narrow one like
    "roles/secretmanager.secretAccessor" is a known, documented quantity,
    and primitive roles (owner/editor/viewer) carry thousands of
    permissions that would drown the report. Returns None (not printed) for
    predefined roles or on fetch failure - some custom roles aren't
    readable without extra permissions, same best-effort posture as
    SCC/Recommender."""
    if role in cache:
        return cache[role]
    if not iam or not _is_custom_role(role):
        cache[role] = None
        return None
    try:
        if role.startswith("projects/"):
            perms = iam.projects().roles().get(name=role).execute().get("includedPermissions")
        else:
            perms = iam.organizations().roles().get(name=role).execute().get("includedPermissions")
    except HttpError as e:
        errors.append({"check": f"role_permissions:{role}", "reason": _http_error_reason(e), "detail": str(e)})
        perms = None
    cache[role] = perms
    return perms


def scan_iam_bindings(creds, project_id, errors):
    resources = []
    try:
        crm = build("cloudresourcemanager", "v3", credentials=creds, cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=f"projects/{project_id}", body={}).execute()
    except HttpError as e:
        errors.append({"check": "iam_bindings", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    try:
        iam = build("iam", "v1", credentials=creds, cache_discovery=False)
    except Exception:  # noqa: BLE001 - role-permission expansion is a nice-to-have, not core to this check
        iam = None
    role_cache = {}

    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        included_permissions = _role_included_permissions(iam, role, role_cache, errors)
        for member in binding.get("members", []):
            severity = "high" if role in HIGH_RISK_ROLES else "info"
            is_public_member = member.startswith("allUsers") or member.startswith("allAuthenticatedUsers")
            if is_public_member:
                severity = "critical"
            resources.append({
                "type": "gcp.iam.binding",
                "id": f"binding:{role}:{member}",
                "attributes": {"role": role, "member": member, "included_permissions": included_permissions},
                "severity": severity,
                "tags": ["iam", "binding"] + (["public"] if is_public_member else []),
            })
    return resources


def scan_firewall_rules(creds, project_id, sensitive_ports, errors):
    resources = []
    sensitive_ports = {str(p) for p in sensitive_ports}
    try:
        compute = build("compute", "v1", credentials=creds, cache_discovery=False)
        rules = []
        req = compute.firewalls().list(project=project_id)
        while req is not None:
            resp = req.execute()
            rules.extend(resp.get("items", []))
            req = compute.firewalls().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "firewall_rules", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for rule in rules:
        name = rule.get("name")
        source_ranges = rule.get("sourceRanges", [])
        disabled = rule.get("disabled", False)
        allowed = rule.get("allowed", [])
        is_public = "0.0.0.0/0" in source_ranges

        exposes_sensitive_port = False
        for a in allowed:
            ports = a.get("ports", [])
            if not ports and a.get("IPProtocol") in ("tcp", "udp"):
                exposes_sensitive_port = True  # no ports listed = all ports open
            for p in ports:
                if any(port in p for port in sensitive_ports):
                    exposes_sensitive_port = True

        severity = "info"
        if is_public and not disabled:
            severity = "critical" if exposes_sensitive_port else "high"

        resources.append({
            "type": "gcp.compute.firewall_rule",
            "id": f"fw:{name}",
            "attributes": {
                "name": name,
                "direction": rule.get("direction"),
                "source_ranges": source_ranges,
                "allowed": allowed,
                "disabled": disabled,
                "network": (rule.get("network") or "").rsplit("/", 1)[-1],
            },
            "severity": severity,
            "tags": ["network", "firewall"] + (["public-exposure"] if is_public else []),
        })
    return resources


def _parse_ssh_keys_metadata(value, scope, scope_id):
    resources = []
    for line in (value or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # format: "<username>:<algo> <base64-key> <comment>"
        if ":" in line:
            username, rest = line.split(":", 1)
        else:
            username, rest = "unknown", line
        parts = rest.strip().split()
        algo = parts[0] if parts else "unknown"
        fingerprint = _fingerprint(parts[1]) if len(parts) > 1 else "unknown"
        comment = parts[2] if len(parts) > 2 else ""
        resources.append({
            "type": "gcp.compute.ssh_key_metadata",
            "id": f"ssh:{scope}:{scope_id}:{username}:{fingerprint}",
            "attributes": {
                "scope": scope,
                "scope_id": scope_id,
                "username": username,
                "algorithm": algo,
                "comment": comment,
                "fingerprint": fingerprint,
            },
            "severity": "info",
            "tags": ["network", "ssh_key", scope],
        })
    return resources


def scan_ssh_keys(creds, project_id, errors):
    resources = []
    try:
        compute = build("compute", "v1", credentials=creds, cache_discovery=False)
    except Exception as e:  # noqa: BLE001
        errors.append({"check": "ssh_keys", "reason": "ERROR", "detail": str(e)})
        return resources

    try:
        project = compute.projects().get(project=project_id).execute()
        for item in project.get("commonInstanceMetadata", {}).get("items", []):
            if item.get("key") in ("ssh-keys", "sshKeys"):
                resources.extend(_parse_ssh_keys_metadata(item.get("value"), "project", project_id))
    except HttpError as e:
        errors.append({"check": "ssh_keys_project", "reason": _http_error_reason(e), "detail": str(e)})

    try:
        req = compute.instances().aggregatedList(project=project_id)
        while req is not None:
            resp = req.execute()
            for _, scoped in resp.get("items", {}).items():
                for instance in scoped.get("instances", []):
                    for item in instance.get("metadata", {}).get("items", []):
                        if item.get("key") in ("ssh-keys", "sshKeys"):
                            resources.extend(_parse_ssh_keys_metadata(item.get("value"), "instance", instance.get("name")))
            req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "ssh_keys_instances", "reason": _http_error_reason(e), "detail": str(e)})

    return resources


def scan_api_keys(creds, project_id, errors):
    """API Keys (APIs & Services > Credentials > API keys) - a separate
    credential type from IAM service-account keys, listable via the
    dedicated API Keys API (apikeys.googleapis.com). An API key with no
    restrictions (no API/application/IP restriction set at all) can be used
    to call any enabled API from anywhere, so it's flagged high; a
    restricted key is info. Note: OAuth 2.0 Client IDs, shown on the same
    Credentials page, have no equivalent public API - see the GCP manual
    review URL in the report."""
    resources = []
    try:
        apikeys = build("apikeys", "v2", credentials=creds, cache_discovery=False)
        parent = f"projects/{project_id}/locations/global"
        req = apikeys.projects().locations().keys().list(parent=parent)
        keys = []
        while req is not None:
            resp = req.execute()
            keys.extend(resp.get("keys", []))
            req = apikeys.projects().locations().keys().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "api_keys", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for key in keys:
        restrictions = key.get("restrictions") or {}
        is_unrestricted = not restrictions
        key_id = key.get("uid") or key.get("name", "").rsplit("/", 1)[-1]
        resources.append({
            "type": "gcp.apikeys.key",
            "id": f"api_key:{key_id}",
            "attributes": {
                "display_name": key.get("displayName", ""),
                "create_time": key.get("createTime"),
                "restrictions": sorted(restrictions.keys()),
            },
            "severity": "high" if is_unrestricted else "info",
            "tags": ["iam", "api_key"] + ([] if not is_unrestricted else ["unrestricted"]),
        })

    return resources


def _bearer_headers(creds):
    if not creds.valid or creds.expired:
        creds.refresh(google_auth_transport_requests.Request())
    return {"Authorization": f"Bearer {creds.token}"}


def scan_scc_findings(creds, project_id, errors):
    """Uses Security Command Center's v2 REST API directly (not exposed via
    the discovery client used elsewhere in this file - v1's project-scoped
    findings.list is retired, and v1's org-scoped path needs an
    organization-level role) with a project-scoped parent, which works with
    ordinary project-level IAM roles - no organization-level role grant
    required. Defaults to only ACTIVE findings (state="ACTIVE"); the
    unfiltered finding log for this project runs into the tens of thousands
    including long-resolved findings, which would swamp the report. See
    references/gcp_setup.md.
    """
    resources = []
    url = f"{SCC_V2_BASE}/projects/{project_id}/sources/-/findings"
    params = {"pageSize": 1000, "filter": 'state="ACTIVE"'}

    while True:
        try:
            resp = requests.get(url, headers=_bearer_headers(creds), params=params, timeout=30)
        except requests.RequestException as e:
            errors.append({"check": "scc_findings", "reason": "ERROR", "detail": str(e)})
            return resources

        if resp.status_code != 200:
            reason = "PERMISSION_DENIED" if resp.status_code == 403 else (
                "SERVICE_DISABLED_OR_NOT_FOUND" if resp.status_code == 404 else f"HTTP_{resp.status_code}"
            )
            errors.append({"check": "scc_findings", "reason": reason, "detail": resp.text[:300]})
            return resources

        data = resp.json()
        for item in data.get("listFindingsResults", []):
            finding = item.get("finding", {})
            severity = (finding.get("severity") or "info").lower()
            if severity not in ("critical", "high", "medium", "low"):
                severity = "info"
            resources.append({
                "type": "gcp.scc.finding",
                "id": f"scc:{finding.get('name')}",
                "attributes": {
                    "category": finding.get("category"),
                    "state": finding.get("state"),
                    "resource_name": finding.get("resourceName"),
                },
                "severity": severity,
                "tags": ["scc"],
            })

        page_token = data.get("nextPageToken")
        if not page_token:
            return resources
        params = dict(params, pageToken=page_token)


def scan_iam_recommendations(creds, project_id, errors):
    resources = []
    try:
        service = build("recommender", "v1", credentials=creds, cache_discovery=False)
        parent = f"projects/{project_id}/locations/global/recommenders/google.iam.policy.Recommender"
        recs = []
        req = service.projects().locations().recommenders().recommendations().list(parent=parent, pageSize=1000)
        while req is not None:
            resp = req.execute()
            recs.extend(resp.get("recommendations", []))
            req = service.projects().locations().recommenders().recommendations().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "iam_recommender", "reason": _http_error_reason(e), "detail": str(e)})
        return resources
    except Exception as e:  # noqa: BLE001
        errors.append({"check": "iam_recommender", "reason": "ERROR", "detail": str(e)})
        return resources

    for rec in recs:
        rec_id = rec.get("name", "").rsplit("/", 1)[-1]
        resources.append({
            "type": "gcp.iam.recommendation",
            "id": f"rec:{rec_id}",
            "attributes": {
                "description": rec.get("description"),
                "state": (rec.get("stateInfo") or {}).get("state"),
                "priority": rec.get("priority"),
            },
            "severity": "medium",
            "tags": ["iam", "recommender"],
        })
    return resources


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _latest_nonzero_day(points):
    """points: list of Cloud Monitoring Point dicts, daily-aligned. Returns
    the interval end-time of the most recent point with a nonzero value, or
    None if the series never had activity in the queried window."""
    latest = None
    for p in points:
        value = p.get("value", {})
        raw = value.get("int64Value", value.get("doubleValue"))
        try:
            numeric = float(raw)
        except (TypeError, ValueError):
            continue
        if numeric <= 0:
            continue
        end_time = (p.get("interval") or {}).get("endTime")
        if end_time and (latest is None or end_time > latest):
            latest = end_time
    return latest


def _query_monitoring_metric(monitoring, project_id, metric_type, errors):
    """Returns raw timeSeries dicts for the last 42 days (Cloud Monitoring's
    retention window for these IAM metrics), aligned to daily buckets so
    each series returns at most ~42 points instead of one point per event.
    """
    end = _now()
    start = end - datetime.timedelta(days=42)
    series = []
    page_token = None
    while True:
        params = {
            "name": f"projects/{project_id}",
            "filter": f'metric.type="{metric_type}"',
            "interval_startTime": _iso(start),
            "interval_endTime": _iso(end),
            "aggregation_alignmentPeriod": "86400s",
            "aggregation_perSeriesAligner": "ALIGN_SUM",
        }
        if page_token:
            params["pageToken"] = page_token
        try:
            resp = monitoring.projects().timeSeries().list(**params).execute()
        except HttpError as e:
            errors.append({"check": f"usage_metrics:{metric_type}", "reason": _http_error_reason(e), "detail": str(e)})
            return series
        series.extend(resp.get("timeSeries", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return series


def scan_usage_metrics(creds, project_id, errors):
    """Best-effort: derives the 4 "last seen" columns shown in the GCP
    Console's per-service-account Metrics tab (Service account usage /
    per API, Authentication traffic / per key) from Cloud Monitoring's two
    documented IAM metrics. Requires the Monitoring API enabled and
    roles/monitoring.viewer - degrades to empty results (not a crash) if
    either is missing. Granularity is daily; retention is 6 weeks. See
    references/gcp_setup.md for the exact metrics and label assumptions.
    """
    usage_by_unique_id = {}
    try:
        monitoring = build("monitoring", "v3", credentials=creds, cache_discovery=False)
    except Exception as e:  # noqa: BLE001
        errors.append({"check": "usage_metrics", "reason": "ERROR", "detail": str(e)})
        return usage_by_unique_id

    sa_series = _query_monitoring_metric(monitoring, project_id, "iam.googleapis.com/service_account/authn_events_count", errors)
    key_series = _query_monitoring_metric(monitoring, project_id, "iam.googleapis.com/service_account/key/authn_events_count", errors)

    for ts in sa_series:
        unique_id = ((ts.get("resource") or {}).get("labels") or {}).get("unique_id")
        latest = _latest_nonzero_day(ts.get("points", []))
        if not unique_id or latest is None:
            continue
        entry = usage_by_unique_id.setdefault(unique_id, {})
        if latest > entry.get("usage_last_seen", ""):
            entry["usage_last_seen"] = latest
        # "per API" breakdown: whatever extra metric labels this series carries
        # (e.g. method/service), beyond the metric type itself.
        extra_labels = (ts.get("metric") or {}).get("labels", {})
        label_desc = ",".join(f"{k}={v}" for k, v in sorted(extra_labels.items())) or None
        if label_desc:
            per_api = entry.setdefault("_usage_per_api", {})
            if latest > per_api.get(label_desc, ""):
                per_api[label_desc] = latest

    for ts in key_series:
        unique_id = ((ts.get("resource") or {}).get("labels") or {}).get("unique_id")
        key_id = (ts.get("metric") or {}).get("labels", {}).get("key_id")
        latest = _latest_nonzero_day(ts.get("points", []))
        if not unique_id or latest is None:
            continue
        entry = usage_by_unique_id.setdefault(unique_id, {})
        if latest > entry.get("key_auth_last_seen", ""):
            entry["key_auth_last_seen"] = latest
        if key_id:
            per_key = entry.setdefault("_key_auth_per_key", {})
            if latest > per_key.get(key_id, ""):
                per_key[key_id] = latest

    # Collapse the per-API/per-key breakdowns to "most recent" for the summary columns.
    for entry in usage_by_unique_id.values():
        per_api = entry.pop("_usage_per_api", {})
        if per_api:
            top_label, top_ts = max(per_api.items(), key=lambda kv: kv[1])
            entry["usage_per_api_last_seen"] = top_ts
            entry["usage_per_api_label"] = top_label
        per_key = entry.pop("_key_auth_per_key", {})
        if per_key:
            top_key, top_ts = max(per_key.items(), key=lambda kv: kv[1])
            entry["key_auth_per_key_last_seen"] = top_ts
            entry["key_auth_per_key_id"] = top_key

    return usage_by_unique_id


CLOUDASSET_V1_BASE = "https://cloudasset.googleapis.com/v1"


def scan_cloud_asset_public_bindings(creds, project_id, errors):
    """Uses Cloud Asset Inventory's searchAllIamPolicies (raw REST - same
    _bearer_headers pattern as scan_scc_findings; not exposed via the
    discovery client) to find IAM policy bindings granting allUsers/
    allAuthenticatedUsers on ANY resource in the project (buckets, BigQuery
    datasets, Pub/Sub topics, Cloud Functions, etc.), not just the
    project-level policy scan_iam_bindings already covers. Requires
    roles/cloudasset.viewer."""
    resources = []
    url = f"{CLOUDASSET_V1_BASE}/projects/{project_id}:searchAllIamPolicies"
    params = {"query": "policy:(allUsers OR allAuthenticatedUsers)", "pageSize": 500}

    while True:
        try:
            resp = requests.get(url, headers=_bearer_headers(creds), params=params, timeout=30)
        except requests.RequestException as e:
            errors.append({"check": "cloud_asset_public_bindings", "reason": "ERROR", "detail": str(e)})
            return resources

        if resp.status_code != 200:
            reason = "PERMISSION_DENIED" if resp.status_code == 403 else (
                "SERVICE_DISABLED_OR_NOT_FOUND" if resp.status_code == 404 else f"HTTP_{resp.status_code}"
            )
            errors.append({"check": "cloud_asset_public_bindings", "reason": reason, "detail": resp.text[:300]})
            return resources

        data = resp.json()
        for item in data.get("results", []):
            resource_name = item.get("resource", "")
            asset_type = item.get("assetType", "")
            policy = item.get("policy", {})
            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                for member in binding.get("members", []):
                    if member not in ("allUsers", "allAuthenticatedUsers"):
                        continue
                    resources.append({
                        "type": "gcp.cloudasset.public_binding",
                        "id": f"asset_public_binding:{resource_name}:{role}:{member}",
                        "attributes": {
                            "resource": resource_name,
                            "asset_type": asset_type,
                            "role": role,
                            "member": member,
                        },
                        "severity": "critical",
                        "tags": ["cloudasset", "public"],
                    })

        page_token = data.get("nextPageToken")
        if not page_token:
            return resources
        params = dict(params, pageToken=page_token)


def scan_kms_key_rotation(creds, project_id, errors):
    """Lists Cloud KMS crypto keys across every location and flags keys with
    no automatic rotation configured. Requires roles/cloudkms.viewer."""
    resources = []
    try:
        kms = build("cloudkms", "v1", credentials=creds, cache_discovery=False)
        locations = [
            loc["locationId"]
            for loc in kms.projects().locations().list(name=f"projects/{project_id}").execute().get("locations", [])
        ]
    except HttpError as e:
        errors.append({"check": "kms_key_rotation", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for location in locations:
        try:
            parent = f"projects/{project_id}/locations/{location}"
            key_rings = []
            req = kms.projects().locations().keyRings().list(parent=parent)
            while req is not None:
                resp = req.execute()
                key_rings.extend(resp.get("keyRings", []))
                req = kms.projects().locations().keyRings().list_next(previous_request=req, previous_response=resp)
        except HttpError as e:
            errors.append({"check": f"kms_key_rings:{location}", "reason": _http_error_reason(e), "detail": str(e)})
            continue

        for ring in key_rings:
            try:
                keys = []
                req = kms.projects().locations().keyRings().cryptoKeys().list(parent=ring["name"])
                while req is not None:
                    resp = req.execute()
                    keys.extend(resp.get("cryptoKeys", []))
                    req = kms.projects().locations().keyRings().cryptoKeys().list_next(previous_request=req, previous_response=resp)
            except HttpError as e:
                errors.append({"check": f"kms_crypto_keys:{ring['name']}", "reason": _http_error_reason(e), "detail": str(e)})
                continue

            for key in keys:
                name = key.get("name", "")
                has_rotation = bool(key.get("rotationPeriod"))
                resources.append({
                    "type": "gcp.kms.key",
                    "id": f"kms_key:{name}",
                    "attributes": {
                        "name": name,
                        "location": location,
                        "key_ring": ring.get("name", "").rsplit("/", 1)[-1],
                        "purpose": key.get("purpose"),
                        "rotation_period": key.get("rotationPeriod"),
                        "next_rotation_time": key.get("nextRotationTime"),
                    },
                    "severity": "high" if not has_rotation and key.get("purpose") == "ENCRYPT_DECRYPT" else "info",
                    "tags": ["kms"] + ([] if has_rotation else ["no-rotation"]),
                })

    return resources


def scan_cloud_sql_instances(creds, project_id, errors):
    """Lists Cloud SQL instances and flags public IP with unrestricted
    authorized networks or SSL not required. Requires roles/cloudsql.viewer."""
    resources = []
    try:
        sqladmin = build("sqladmin", "v1", credentials=creds, cache_discovery=False)
        instances = []
        req = sqladmin.instances().list(project=project_id)
        while req is not None:
            resp = req.execute()
            instances.extend(resp.get("items", []))
            req = sqladmin.instances().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "cloud_sql_instances", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for inst in instances:
        settings = inst.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})
        require_ssl = ip_config.get("requireSsl", False) or ip_config.get("sslMode") in (
            "TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "ENCRYPTED_ONLY",
        )
        authorized_networks = [
            {"value": n.get("value"), "name": n.get("name")} for n in ip_config.get("authorizedNetworks", [])
        ]
        has_public_ip = any(a.get("type") == "PRIMARY" for a in inst.get("ipAddresses", []))
        is_open = any(n["value"] == "0.0.0.0/0" for n in authorized_networks)

        severity = "info"
        if is_open:
            severity = "critical"
        elif has_public_ip and not require_ssl:
            severity = "high"

        resources.append({
            "type": "gcp.cloudsql.instance",
            "id": f"sql_instance:{inst.get('name')}",
            "attributes": {
                "name": inst.get("name"),
                "database_version": inst.get("databaseVersion"),
                "require_ssl": require_ssl,
                "has_public_ip": has_public_ip,
                "authorized_networks": authorized_networks,
                "backup_enabled": (settings.get("backupConfiguration") or {}).get("enabled", False),
            },
            "severity": severity,
            "tags": ["cloudsql"] + (["public-exposure"] if is_open else []),
        })

    return resources


def scan_secret_manager_secrets(creds, project_id, errors):
    """Lists Secret Manager secrets and flags those with no rotation policy
    configured. Requires roles/secretmanager.viewer."""
    resources = []
    try:
        secretmanager = build("secretmanager", "v1", credentials=creds, cache_discovery=False)
        secrets = []
        req = secretmanager.projects().secrets().list(parent=f"projects/{project_id}")
        while req is not None:
            resp = req.execute()
            secrets.extend(resp.get("secrets", []))
            req = secretmanager.projects().secrets().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "secret_manager_secrets", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for secret in secrets:
        name = secret.get("name", "")
        rotation = secret.get("rotation") or {}
        has_rotation = bool(rotation.get("rotationPeriod") or rotation.get("nextRotationTime"))
        resources.append({
            "type": "gcp.secretmanager.secret",
            "id": f"secret:{name}",
            "attributes": {
                "name": name.rsplit("/", 1)[-1],
                "create_time": secret.get("createTime"),
                "rotation_period": rotation.get("rotationPeriod"),
                "next_rotation_time": rotation.get("nextRotationTime"),
            },
            "severity": "low" if not has_rotation else "info",
            "tags": ["secretmanager"] + ([] if has_rotation else ["no-rotation"]),
        })

    return resources


def scan_logging_sinks(creds, project_id, errors):
    """Lists Cloud Logging sinks and flags whether any exports logs to a
    destination outside this project (an external/immutable audit trail).
    Requires roles/logging.viewer."""
    resources = []
    try:
        logging_svc = build("logging", "v2", credentials=creds, cache_discovery=False)
        sinks = []
        req = logging_svc.projects().sinks().list(parent=f"projects/{project_id}")
        while req is not None:
            resp = req.execute()
            sinks.extend(resp.get("sinks", []))
            req = logging_svc.projects().sinks().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "logging_sinks", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for sink in sinks:
        destination = sink.get("destination", "")
        is_external = f"projects/{project_id}" not in destination
        resources.append({
            "type": "gcp.logging.sink",
            "id": f"log_sink:{sink.get('name')}",
            "attributes": {
                "name": sink.get("name"),
                "destination": destination,
                "filter": sink.get("filter", ""),
                "disabled": sink.get("disabled", False),
            },
            "severity": "info",
            "tags": ["logging"] + (["external-destination"] if is_external else []),
        })

    return resources


def scan_artifact_registry_repos(creds, project_id, errors):
    """Lists Artifact Registry repositories across every location and flags
    any with a public (allUsers/allAuthenticatedUsers) IAM binding. Requires
    roles/artifactregistry.reader."""
    resources = []
    try:
        ar = build("artifactregistry", "v1", credentials=creds, cache_discovery=False)
        locations = [
            loc["locationId"]
            for loc in ar.projects().locations().list(name=f"projects/{project_id}").execute().get("locations", [])
        ]
    except HttpError as e:
        errors.append({"check": "artifact_registry_repos", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for location in locations:
        try:
            repos = []
            parent = f"projects/{project_id}/locations/{location}"
            req = ar.projects().locations().repositories().list(parent=parent)
            while req is not None:
                resp = req.execute()
                repos.extend(resp.get("repositories", []))
                req = ar.projects().locations().repositories().list_next(previous_request=req, previous_response=resp)
        except HttpError as e:
            errors.append({"check": f"artifact_registry_repos:{location}", "reason": _http_error_reason(e), "detail": str(e)})
            continue

        for repo in repos:
            name = repo.get("name", "")
            public_members = []
            try:
                policy = ar.projects().locations().repositories().getIamPolicy(resource=name).execute()
                for binding in policy.get("bindings", []):
                    for member in binding.get("members", []):
                        if member in ("allUsers", "allAuthenticatedUsers"):
                            public_members.append(f"{binding.get('role')}:{member}")
            except HttpError as e:
                errors.append({"check": f"artifact_registry_policy:{name}", "reason": _http_error_reason(e), "detail": str(e)})

            resources.append({
                "type": "gcp.artifactregistry.repository",
                "id": f"ar_repo:{name}",
                "attributes": {
                    "name": name.rsplit("/", 1)[-1],
                    "location": location,
                    "format": repo.get("format"),
                    "public_bindings": public_members,
                },
                "severity": "critical" if public_members else "info",
                "tags": ["artifactregistry"] + (["public"] if public_members else []),
            })

    return resources


def scan_pubsub_public_topics(creds, project_id, errors):
    """Lists Pub/Sub topics and flags any with a public IAM binding.
    Requires roles/pubsub.viewer to list topics, but getIamPolicy on a topic
    needs pubsub.topics.getIamPolicy - a permission only roles/pubsub.editor
    and roles/pubsub.admin carry (confirmed against live docs), not
    roles/pubsub.viewer, and neither of those is appropriate to grant a
    read-only scanner. So per-topic policy checks are attempted once; the
    first permission-denied response is treated as systemic (it will be
    identical for every topic) and the rest are left as "unknown" rather
    than repeating the same 403 dozens of times in the report."""
    resources = []
    try:
        pubsub = build("pubsub", "v1", credentials=creds, cache_discovery=False)
        topics = []
        req = pubsub.projects().topics().list(project=f"projects/{project_id}")
        while req is not None:
            resp = req.execute()
            topics.extend(resp.get("topics", []))
            req = pubsub.projects().topics().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "pubsub_topics", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    policy_checks_disabled = False
    for topic in topics:
        name = topic.get("name", "")
        public_members = [] if not policy_checks_disabled else None
        if not policy_checks_disabled:
            try:
                policy = pubsub.projects().topics().getIamPolicy(resource=name).execute()
                for binding in policy.get("bindings", []):
                    for member in binding.get("members", []):
                        if member in ("allUsers", "allAuthenticatedUsers"):
                            public_members.append(f"{binding.get('role')}:{member}")
            except HttpError as e:
                errors.append({"check": "pubsub_topic_policy", "reason": _http_error_reason(e), "detail": str(e)})
                policy_checks_disabled = True
                public_members = None

        resources.append({
            "type": "gcp.pubsub.topic",
            "id": f"topic:{name}",
            "attributes": {
                "name": name.rsplit("/", 1)[-1],
                "public_bindings": public_members,
            },
            "severity": "critical" if public_members else "info",
            "tags": ["pubsub"] + (["public"] if public_members else []),
        })

    return resources


def scan_gke_clusters(creds, project_id, errors):
    """Lists GKE clusters across all locations and flags weak security
    configuration (legacy ABAC, basic/client-cert auth, no private nodes, no
    master-authorized-networks allowlist). Requires roles/container.viewer."""
    resources = []
    try:
        container = build("container", "v1", credentials=creds, cache_discovery=False)
        parent = f"projects/{project_id}/locations/-"
        resp = container.projects().locations().clusters().list(parent=parent).execute()
        clusters = resp.get("clusters", [])
    except HttpError as e:
        errors.append({"check": "gke_clusters", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for cluster in clusters:
        name = cluster.get("name", "")
        private_nodes = bool((cluster.get("privateClusterConfig") or {}).get("enablePrivateNodes"))
        master_networks_enabled = bool((cluster.get("masterAuthorizedNetworksConfig") or {}).get("enabled"))
        legacy_abac = bool((cluster.get("legacyAbac") or {}).get("enabled"))
        network_policy = bool((cluster.get("networkPolicy") or {}).get("enabled"))
        master_auth = cluster.get("masterAuth") or {}
        basic_auth = bool(master_auth.get("username"))
        client_cert = bool(master_auth.get("clientCertificateConfig", {}).get("issueClientCertificate"))
        workload_identity_enabled = bool((cluster.get("workloadIdentityConfig") or {}).get("workloadPool"))
        binary_auth = cluster.get("binaryAuthorization") or {}
        binary_auth_enabled = binary_auth.get("evaluationMode") not in (None, "DISABLED") or bool(binary_auth.get("enabled"))

        severity = "info"
        if legacy_abac or basic_auth or client_cert:
            severity = "critical"
        elif not private_nodes or not master_networks_enabled:
            severity = "high"
        elif not workload_identity_enabled:
            severity = "low"

        resources.append({
            "type": "gcp.gke.cluster",
            "id": f"gke_cluster:{cluster.get('location')}:{name}",
            "attributes": {
                "name": name,
                "location": cluster.get("location"),
                "private_nodes": private_nodes,
                "master_authorized_networks_enabled": master_networks_enabled,
                "legacy_abac_enabled": legacy_abac,
                "network_policy_enabled": network_policy,
                "basic_auth_enabled": basic_auth,
                "client_cert_auth_enabled": client_cert,
                "workload_identity_enabled": workload_identity_enabled,
                "binary_authorization_enabled": binary_auth_enabled,
            },
            "severity": severity,
            "tags": ["gke"] + ([] if workload_identity_enabled else ["no-workload-identity"]),
        })

    return resources


def scan_storage_bucket_config(creds, project_id, errors):
    """Lists GCS buckets and flags weak hardening config beyond IAM
    (uniform bucket-level access off, public access prevention not
    enforced, versioning off). Complements the Cloud Asset public-bindings
    check, which already covers who has access - this covers the bucket's
    own defenses. Requires storage.buckets.list/get - granted by
    roles/storage.admin, or the narrower per-bucket
    roles/storage.legacyBucketReader bound at the project level."""
    resources = []
    try:
        storage = build("storage", "v1", credentials=creds, cache_discovery=False)
        buckets = []
        req = storage.buckets().list(project=project_id)
        while req is not None:
            resp = req.execute()
            buckets.extend(resp.get("items", []))
            req = storage.buckets().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "storage_bucket_config", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for bucket in buckets:
        name = bucket.get("name")
        iam_config = bucket.get("iamConfiguration") or {}
        uniform_access = bool((iam_config.get("uniformBucketLevelAccess") or {}).get("enabled"))
        public_access_prevention = iam_config.get("publicAccessPrevention", "inherited")
        versioning_enabled = bool((bucket.get("versioning") or {}).get("enabled"))

        severity = "info"
        tags = ["storage"]
        if public_access_prevention != "enforced":
            severity = "medium"
            tags.append("no-public-access-prevention")
        elif not uniform_access:
            severity = "low"
            tags.append("no-uniform-access")

        resources.append({
            "type": "gcp.storage.bucket_config",
            "id": f"bucket_config:{name}",
            "attributes": {
                "name": name,
                "uniform_bucket_level_access": uniform_access,
                "public_access_prevention": public_access_prevention,
                "versioning_enabled": versioning_enabled,
                "location": bucket.get("location"),
            },
            "severity": severity,
            "tags": tags,
        })

    return resources


ORG_POLICY_CONSTRAINTS = [
    "constraints/iam.allowedPolicyMemberDomains",
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/iam.disableServiceAccountKeyUpload",
    "constraints/iam.disableServiceAccountCreation",
    "constraints/sql.restrictPublicIp",
    "constraints/sql.restrictAuthorizedNetworks",
    "constraints/compute.vmExternalIpAccess",
    "constraints/compute.requireOsLogin",
    "constraints/compute.requireShieldedVm",
    "constraints/compute.disableSerialPortAccess",
    "constraints/compute.skipDefaultNetworkCreation",
    "constraints/compute.restrictVpcPeering",
    "constraints/storage.publicAccessPrevention",
    "constraints/storage.uniformBucketLevelAccess",
]


def _org_policy_rule_is_protected(rule):
    """Interprets one Org Policy effective-policy rule to determine whether
    it's actually restrictive - this curated set mixes boolean constraints
    (a rule with an "enforce" key) and list constraints (a rule with
    "allowAll"/"denyAll"/"values"), and naively treating "a rule exists at
    all" as "protected" (the previous approach) gets every list constraint
    backwards: a live effective policy of {"allowAll": true} IS a rule, but
    it means the constraint places no restriction whatsoever - confirmed
    live against this project, where iam.allowedPolicyMemberDomains and
    compute.vmExternalIpAccess both came back as exactly that shape."""
    if "enforce" in rule:
        return bool(rule["enforce"])
    if rule.get("denyAll"):
        return True
    if rule.get("allowAll"):
        return False
    values = rule.get("values") or {}
    if values.get("deniedValues") or values.get("allowedValues"):
        return True
    return False


def _org_policy_is_enforced(rules):
    """A constraint counts as enforced only if every applicable rule is
    itself restrictive - an empty rules list means nothing is explicitly
    set (inherited default), not enforced."""
    return bool(rules) and all(_org_policy_rule_is_protected(r) for r in rules)


def scan_org_policies(creds, project_id, errors):
    """Reads the effective state of a curated set of security-relevant Org
    Policy constraints (domain-restricted sharing, service account key
    creation/upload/creation, Cloud SQL public IP/authorized networks, VM
    external IP, OS Login, Shielded VM, serial port access, default network
    creation, VPC peering, bucket public access prevention, uniform
    bucket-level access) at the project scope. Purely informational -
    whether these constraints "should" be enforced is an organizational
    choice, not a universal best practice, so severity stays at "info"
    throughout; this is an inventory chapter, not a findings one (the
    report highlights unenforced constraints visually instead of scoring
    them). Requires roles/orgpolicy.policyViewer and the Organization
    Policy API (orgpolicy.googleapis.com) enabled - each constraint
    degrades to a skipped-check entry independently on any error (disabled
    API, missing permission, etc.), same best-effort posture as every
    other check in this file."""
    resources = []
    try:
        orgpolicy = build("orgpolicy", "v2", credentials=creds, cache_discovery=False)
    except Exception as e:  # noqa: BLE001
        errors.append({"check": "org_policies", "reason": "ERROR", "detail": str(e)})
        return resources

    for constraint in ORG_POLICY_CONSTRAINTS:
        policy_name = f"projects/{project_id}/policies/{constraint.rsplit('/', 1)[-1]}"
        try:
            policy = orgpolicy.projects().policies().getEffectivePolicy(name=policy_name).execute()
        except HttpError as e:
            errors.append({"check": f"org_policy:{constraint}", "reason": _http_error_reason(e), "detail": str(e)})
            continue

        spec = policy.get("spec") or {}
        rules = spec.get("rules", [])
        enforced = _org_policy_is_enforced(rules)
        resources.append({
            "type": "gcp.orgpolicy.constraint",
            "id": f"org_policy:{constraint}",
            "attributes": {"constraint": constraint, "enforced": enforced, "rules": rules},
            "severity": "info",
            "tags": ["orgpolicy"] + ([] if enforced else ["not-enforced"]),
        })

    return resources


def scan_dns_zones(creds, project_id, errors):
    """Lists Cloud DNS managed zones and flags public zones without DNSSEC
    enabled. Requires roles/dns.reader."""
    resources = []
    try:
        dns = build("dns", "v1", credentials=creds, cache_discovery=False)
        zones = []
        req = dns.managedZones().list(project=project_id)
        while req is not None:
            resp = req.execute()
            zones.extend(resp.get("managedZones", []))
            req = dns.managedZones().list_next(previous_request=req, previous_response=resp)
    except HttpError as e:
        errors.append({"check": "dns_zones", "reason": _http_error_reason(e), "detail": str(e)})
        return resources

    for zone in zones:
        visibility = zone.get("visibility", "public")
        dnssec_state = (zone.get("dnssecConfig") or {}).get("state", "off")
        is_public = visibility == "public"
        resources.append({
            "type": "gcp.dns.zone",
            "id": f"dns_zone:{zone.get('name')}",
            "attributes": {
                "name": zone.get("name"),
                "dns_name": zone.get("dnsName"),
                "visibility": visibility,
                "dnssec_state": dnssec_state,
            },
            "severity": "medium" if is_public and dnssec_state != "on" else "info",
            "tags": ["dns"] + (["no-dnssec"] if is_public and dnssec_state != "on" else []),
        })

    return resources


def scan(config, project_id, checks_cfg, errors):
    """Run all enabled GCP checks for one project. Returns list[Resource dict]."""
    creds = _credentials(config["gcp"]["_key_path_resolved"])
    resources = []

    if checks_cfg.get("service_account_keys", True):
        sa_key_resources = scan_iam_service_accounts_and_keys(
            creds, project_id,
            config["gcp"].get("key_age_warn_days", 90),
            config["gcp"].get("key_age_critical_days", 180),
            errors,
        )
        if checks_cfg.get("usage_metrics", True):
            usage_by_unique_id = scan_usage_metrics(creds, project_id, errors)
            for r in sa_key_resources:
                if r["type"] != "gcp.iam.service_account":
                    continue
                usage = usage_by_unique_id.get(r["attributes"].get("unique_id"), {})
                r["attributes"]["last_seen_usage"] = usage.get("usage_last_seen")
                r["attributes"]["last_seen_usage_per_api"] = usage.get("usage_per_api_last_seen")
                r["attributes"]["last_seen_usage_per_api_label"] = usage.get("usage_per_api_label")
                r["attributes"]["last_seen_key_auth"] = usage.get("key_auth_last_seen")
                r["attributes"]["last_seen_key_auth_per_key"] = usage.get("key_auth_per_key_last_seen")
                r["attributes"]["last_seen_key_auth_per_key_id"] = usage.get("key_auth_per_key_id")
        resources += sa_key_resources
    if checks_cfg.get("iam_bindings", True):
        resources += scan_iam_bindings(creds, project_id, errors)
    if checks_cfg.get("firewall_rules", True):
        resources += scan_firewall_rules(creds, project_id, config["gcp"].get("sensitive_ports", []), errors)
    if checks_cfg.get("ssh_keys", True):
        resources += scan_ssh_keys(creds, project_id, errors)
    if checks_cfg.get("api_keys", True):
        resources += scan_api_keys(creds, project_id, errors)
    if checks_cfg.get("scc_findings", True):
        resources += scan_scc_findings(creds, project_id, errors)
    if checks_cfg.get("iam_recommender", True):
        resources += scan_iam_recommendations(creds, project_id, errors)
    if checks_cfg.get("cloud_asset_public_bindings", True):
        resources += scan_cloud_asset_public_bindings(creds, project_id, errors)
    if checks_cfg.get("kms_key_rotation", True):
        resources += scan_kms_key_rotation(creds, project_id, errors)
    if checks_cfg.get("cloud_sql_instances", True):
        resources += scan_cloud_sql_instances(creds, project_id, errors)
    if checks_cfg.get("secret_manager_secrets", True):
        resources += scan_secret_manager_secrets(creds, project_id, errors)
    if checks_cfg.get("logging_sinks", True):
        resources += scan_logging_sinks(creds, project_id, errors)
    if checks_cfg.get("artifact_registry_repos", True):
        resources += scan_artifact_registry_repos(creds, project_id, errors)
    if checks_cfg.get("pubsub_public_topics", True):
        resources += scan_pubsub_public_topics(creds, project_id, errors)
    if checks_cfg.get("gke_clusters", True):
        resources += scan_gke_clusters(creds, project_id, errors)
    if checks_cfg.get("dns_zones", True):
        resources += scan_dns_zones(creds, project_id, errors)
    if checks_cfg.get("storage_bucket_config", True):
        resources += scan_storage_bucket_config(creds, project_id, errors)
    if checks_cfg.get("org_policies", True):
        resources += scan_org_policies(creds, project_id, errors)

    return resources
