"""Bitbucket provider scanner: workspaces, projects, repos, per-repo access
levels, deploy keys (repo- and project-scoped), SSH keys (on the workspace's
own account and every member's account), webhooks, and branch restrictions.

Note: Bitbucket's public REST API has no endpoint to list Access Tokens
(repo-, project-, or workspace-scoped) - every plausible path 404s with
"There is no API hosted at this URL", not a permission error, at every
scope level tried. That's a platform limitation, not a scope problem this
scanner can work around, so Access Tokens are intentionally not scanned.

Every check surfaces a non-404 HTTP status (403 included) as a skipped
check in `errors` rather than swallowing it - a 403 here almost always
means the configured token is missing a required scope (Bitbucket's error
body names exactly which one), which is actionable information the caller
needs, not a "this resource has zero items" result. Only a 404 (the
resource genuinely doesn't exist, e.g. no branch restrictions configured)
is treated as "no data" and skipped silently.
"""
import os

import requests

from common.redact import register_secret

API_BASE = "https://api.bitbucket.org/2.0"


class BitbucketAuthError(Exception):
    pass


def _load_token(token_path):
    with open(token_path, "r", encoding="utf-8") as f:
        token = f.read().strip()
    register_secret(token)
    return token


def detect_auth_mode(token, account_email=None, configured_mode="auto", workspaces=None):
    """Bitbucket API tokens are ambiguous from the raw string alone - they can
    be a legacy Atlassian account API token (HTTP Basic + email) or a
    workspace/repo access token (Bearer). Returns (mode, session).
    """
    if configured_mode == "bearer":
        session = requests.Session()
        session.headers["Authorization"] = f"Bearer {token}"
        return "bearer", session

    if configured_mode == "basic_email":
        if not account_email:
            raise BitbucketAuthError("bitbucket.account_email must be set in config for auth_mode: basic_email")
        session = requests.Session()
        session.auth = (account_email, token)
        return "basic_email", session

    # auto-detect, tiered from broadest to narrowest scope
    bearer_session = requests.Session()
    bearer_session.headers["Authorization"] = f"Bearer {token}"
    resp = bearer_session.get(f"{API_BASE}/workspaces", params={"pagelen": 1})
    if resp.status_code == 200:
        return "bearer", bearer_session

    if account_email:
        basic_session = requests.Session()
        basic_session.auth = (account_email, token)
        resp = basic_session.get(f"{API_BASE}/user")
        if resp.status_code == 200:
            return "basic_email", basic_session

    for ws in (workspaces or []):
        resp = bearer_session.get(f"{API_BASE}/workspaces/{ws}")
        if resp.status_code == 200:
            return "bearer", bearer_session

    raise BitbucketAuthError(
        "Could not authenticate to Bitbucket with Bearer or Basic auth. If this is a legacy "
        "Atlassian API token, set bitbucket.account_email in config. See references/bitbucket_setup.md."
    )


def discover_workspaces(session, configured_workspaces):
    if configured_workspaces:
        return list(configured_workspaces)
    workspaces = []
    url, params = f"{API_BASE}/workspaces", {"pagelen": 100}
    while url:
        resp = session.get(url, params=params)
        params = None
        resp.raise_for_status()
        data = resp.json()
        workspaces.extend(v["slug"] for v in data.get("values", []))
        url = data.get("next")
    return workspaces


def list_repos(session, workspace, errors):
    repos = []
    url, params = f"{API_BASE}/repositories/{workspace}", {"pagelen": 100}
    while url:
        resp = session.get(url, params=params)
        params = None
        if resp.status_code != 200:
            errors.append({"check": f"list_repos:{workspace}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
            break
        data = resp.json()
        repos.extend(data.get("values", []))
        url = data.get("next")
    return repos


def list_projects(session, workspace, errors):
    projects = []
    url, params = f"{API_BASE}/workspaces/{workspace}/projects", {"pagelen": 100}
    while url:
        resp = session.get(url, params=params)
        params = None
        if resp.status_code != 200:
            errors.append({"check": f"list_projects:{workspace}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
            break
        data = resp.json()
        projects.extend(data.get("values", []))
        url = data.get("next")
    return projects


def scan_project_access_keys(session, workspace, project_key, errors):
    """SSH access keys granted read-only access to every repo in a project
    (Project settings > Access keys in the UI). Confirmed to be a real
    endpoint (403s on missing scope, not 404s on a bad path) - needs both
    `project` and `project:admin` scope; a token with only `project` will
    403 here."""
    resources = []
    url, params = f"{API_BASE}/workspaces/{workspace}/projects/{project_key}/deploy-keys", {"pagelen": 100}
    while url:
        resp = session.get(url, params=params)
        params = None
        if resp.status_code != 200:
            if resp.status_code != 404:
                errors.append({"check": f"project_access_keys:{workspace}/{project_key}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
            break
        data = resp.json()
        for key in data.get("values", []):
            resources.append({
                "type": "bitbucket.project_access_key",
                "id": f"project_key:{workspace}:{project_key}:{key.get('id')}",
                "attributes": {
                    "workspace": workspace, "project_key": project_key, "key_id": key.get("id"),
                    "label": key.get("label"), "comment": key.get("comment"),
                },
                "severity": "medium",
                "tags": ["bitbucket", "access_key"],
            })
        url = data.get("next")
    return resources


def scan_repo_permissions(session, workspace, repo_slug, errors):
    resources = []
    url = f"{API_BASE}/workspaces/{workspace}/permissions/repositories/{repo_slug}"
    params = {"pagelen": 100}
    while url:
        resp = session.get(url, params=params)
        params = None
        if resp.status_code != 200:
            errors.append({"check": f"repo_permissions:{workspace}/{repo_slug}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
            break
        data = resp.json()
        for entry in data.get("values", []):
            user = entry.get("user") or {}
            principal = user.get("nickname") or user.get("uuid") or "unknown"
            permission = entry.get("permission")
            resources.append({
                "type": "bitbucket.repo_permission",
                "id": f"perm:{workspace}:{repo_slug}:{principal}",
                "attributes": {"workspace": workspace, "repo_slug": repo_slug, "principal": principal, "permission": permission},
                "severity": "high" if permission == "admin" else "info",
                "tags": ["bitbucket", "access"],
            })
        url = data.get("next")
    return resources


def scan_deploy_keys(session, workspace, repo_slug, errors):
    resources = []
    resp = session.get(f"{API_BASE}/repositories/{workspace}/{repo_slug}/deploy-keys")
    if resp.status_code != 200:
        if resp.status_code != 404:
            errors.append({"check": f"deploy_keys:{workspace}/{repo_slug}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
        return resources
    for key in resp.json().get("values", []):
        resources.append({
            "type": "bitbucket.deploy_key",
            "id": f"deploy_key:{workspace}:{repo_slug}:{key.get('id')}",
            "attributes": {
                "workspace": workspace, "repo_slug": repo_slug, "key_id": key.get("id"),
                "label": key.get("label"), "comment": key.get("comment"),
            },
            "severity": "medium",
            "tags": ["bitbucket", "deploy_key"],
        })
    return resources


def scan_webhooks(session, workspace, repo_slug, errors):
    resources = []
    url, params = f"{API_BASE}/repositories/{workspace}/{repo_slug}/hooks", {"pagelen": 100}
    while url:
        resp = session.get(url, params=params)
        params = None
        if resp.status_code != 200:
            if resp.status_code != 404:
                errors.append({"check": f"webhooks:{workspace}/{repo_slug}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
            break
        data = resp.json()
        for hook in data.get("values", []):
            resources.append({
                "type": "bitbucket.webhook",
                "id": f"webhook:{workspace}:{repo_slug}:{hook.get('uuid')}",
                "attributes": {
                    "workspace": workspace, "repo_slug": repo_slug, "webhook_id": hook.get("uuid"),
                    "url": hook.get("url"), "events": hook.get("events", []), "active": hook.get("active"),
                },
                "severity": "info",
                "tags": ["bitbucket", "webhook"],
            })
        url = data.get("next")
    return resources


def _fetch_ssh_keys_for_account(session, workspace, account_id, account_label, errors):
    """SSH keys registered on one Bitbucket account - a workspace is itself
    an account (the old "team" concept), which is why "Workspace settings >
    Security > SSH keys" in the UI is this same endpoint pointed at the
    workspace's own slug/UUID rather than a member's. Note: as of writing,
    Bitbucket rejects GET /users/{id}/ssh-keys outright for Bearer
    (access-token) auth with "This API is not accessible by this
    authentication mechanism" - not a scope problem, a hard restriction on
    that auth type. It may still work under auth_mode: basic_email (legacy
    Atlassian API token + account email)."""
    resources = []
    resp = session.get(f"{API_BASE}/users/{account_id}/ssh-keys", params={"pagelen": 100})
    if resp.status_code != 200:
        if resp.status_code != 404:
            errors.append({"check": f"account_ssh_keys:{account_label}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
        return resources
    for key in resp.json().get("values", []):
        resources.append({
            "type": "bitbucket.account_ssh_key",
            "id": f"account_ssh_key:{workspace}:{account_label}:{key.get('uuid')}",
            "attributes": {
                "workspace": workspace, "account": account_label, "key_id": key.get("uuid"),
                "label": key.get("label"), "comment": key.get("comment"),
                "last_used": key.get("last_used"),
            },
            "severity": "medium",
            "tags": ["bitbucket", "ssh_key"],
        })
    return resources


def scan_account_ssh_keys(session, workspace, errors):
    """SSH keys on the workspace's own account plus every workspace
    member's account."""
    resources = _fetch_ssh_keys_for_account(session, workspace, workspace, f"{workspace} (workspace)", errors)

    url, params = f"{API_BASE}/workspaces/{workspace}/members", {"pagelen": 100}
    while url:
        resp = session.get(url, params=params)
        params = None
        if resp.status_code != 200:
            if resp.status_code != 404:
                errors.append({"check": f"workspace_members:{workspace}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
            return resources
        data = resp.json()
        for entry in data.get("values", []):
            user = entry.get("user") or {}
            uuid = user.get("uuid")
            nickname = user.get("nickname") or uuid or "unknown"
            if not uuid:
                continue
            resources += _fetch_ssh_keys_for_account(session, workspace, uuid, nickname, errors)
        url = data.get("next")
    return resources


def scan_branch_restrictions(session, workspace, repo_slug, errors):
    resources = []
    url, params = f"{API_BASE}/repositories/{workspace}/{repo_slug}/branch-restrictions", {"pagelen": 100}
    while url:
        resp = session.get(url, params=params)
        params = None
        if resp.status_code != 200:
            if resp.status_code != 404:
                errors.append({"check": f"branch_restrictions:{workspace}/{repo_slug}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
            break
        data = resp.json()
        for restr in data.get("values", []):
            resources.append({
                "type": "bitbucket.branch_restriction",
                "id": f"branch_restriction:{workspace}:{repo_slug}:{restr.get('id')}",
                "attributes": {
                    "workspace": workspace, "repo_slug": repo_slug, "restriction_id": restr.get("id"),
                    "kind": restr.get("kind"), "pattern": restr.get("pattern"),
                },
                "severity": "info",
                "tags": ["bitbucket", "branch_protection"],
            })
        url = data.get("next")
    return resources


def scan(config, errors):
    """Returns (resources, status)."""
    token_path = config["bitbucket"]["_token_path_resolved"]
    if not os.path.exists(token_path):
        errors.append({"check": "bitbucket_auth", "reason": "MISSING_CREDENTIALS", "detail": f"No token file at {token_path}"})
        return [], "error"

    token = _load_token(token_path)
    bb_cfg = config["bitbucket"]

    account_email = bb_cfg.get("account_email")
    email_path = bb_cfg.get("_account_email_path_resolved")
    if email_path and os.path.exists(email_path):
        with open(email_path, "r", encoding="utf-8") as f:
            account_email = f.read().strip()
        # Deliberately NOT registered as a secret: this is a real person's
        # email that can legitimately appear in Bitbucket data itself (repo
        # permissions, SSH key ownership) - see the same fix applied to the
        # gsuite delegated admin email for why blanket-registering an
        # identifier that doubles as report content backfires.

    try:
        _, session = detect_auth_mode(token, account_email, bb_cfg.get("auth_mode", "auto"), bb_cfg.get("workspaces"))
    except BitbucketAuthError as e:
        errors.append({"check": "bitbucket_auth", "reason": "AUTH_FAILED", "detail": str(e)})
        return [], "error"

    resources = []
    workspaces = discover_workspaces(session, bb_cfg.get("workspaces"))

    for workspace in workspaces:
        if bb_cfg.get("include_account_ssh_keys", True):
            resources += scan_account_ssh_keys(session, workspace, errors)

        if bb_cfg.get("include_project_access_keys", True):
            for project in list_projects(session, workspace, errors):
                resources += scan_project_access_keys(session, workspace, project["key"], errors)

        for repo in list_repos(session, workspace, errors):
            repo_slug = repo["slug"]
            is_private = repo.get("is_private", True)

            resources.append({
                "type": "bitbucket.repo",
                "id": f"repo:{workspace}:{repo_slug}",
                "attributes": {
                    "workspace": workspace, "repo_slug": repo_slug, "is_private": is_private,
                    "updated_on": repo.get("updated_on"),
                },
                "severity": "info" if is_private else "high",
                "tags": ["bitbucket", "repo"] + ([] if is_private else ["public"]),
            })

            if bb_cfg.get("include_repo_permissions", True):
                resources += scan_repo_permissions(session, workspace, repo_slug, errors)
            if bb_cfg.get("include_deploy_keys", True):
                resources += scan_deploy_keys(session, workspace, repo_slug, errors)
            if bb_cfg.get("include_webhooks", True):
                resources += scan_webhooks(session, workspace, repo_slug, errors)
            if bb_cfg.get("include_branch_restrictions", True):
                resources += scan_branch_restrictions(session, workspace, repo_slug, errors)

    status = "ok" if not errors else "partial"
    return resources, status
