"""Trello provider scanner: organizations, organization-level membership
(admin/normal, unconfirmed/deactivated account health), boards, and
board-level members with their per-board permission level.

Missing credentials are a first-class expected state (a dedicated read-scoped
Trello token has to be set up manually, see references/trello_setup.md) - the
scanner no-ops with a clear message rather than raising.
"""
import json
import os

import requests

from common.redact import register_secret

API_BASE = "https://api.trello.com/1"


def discover_organizations(auth_params, errors):
    resp = requests.get(f"{API_BASE}/members/me/organizations", params=auth_params, timeout=30)
    if resp.status_code != 200:
        errors.append({"check": "trello_discover_organizations", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
        return []
    return [org["id"] for org in resp.json()]


def list_boards(auth_params, org_id, errors):
    resp = requests.get(
        f"{API_BASE}/organizations/{org_id}/boards",
        params={**auth_params, "fields": "name,closed,prefs,dateLastActivity"},
        timeout=30,
    )
    if resp.status_code != 200:
        errors.append({"check": f"trello_list_boards:{org_id}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
        return []
    return resp.json()


def scan_org_members(auth_params, org_id, errors):
    """Workspace-level membership (admin/normal at the *organization* scope,
    distinct from per-board membership_type) plus account health signals -
    unconfirmed (never verified their email) and deactivated (removed from
    the workspace but the membership record lingers). `email` is not
    exposed for other members via this API even with org-admin visibility
    on this token - confirmed live, not a scope gap this scanner can work
    around."""
    resources = []
    resp = requests.get(
        f"{API_BASE}/organizations/{org_id}/memberships",
        params={**auth_params, "member": "true", "member_fields": "fullName,username"},
        timeout=30,
    )
    if resp.status_code != 200:
        errors.append({"check": f"trello_org_members:{org_id}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
        return resources

    for entry in resp.json():
        member = entry.get("member") or {}
        member_id = entry.get("idMember", member.get("id", "unknown"))
        member_type = entry.get("memberType")
        unconfirmed = bool(entry.get("unconfirmed"))
        deactivated = bool(entry.get("deactivated"))

        severity = "info"
        tags = ["trello", "org_member"]
        if deactivated:
            severity = "medium"
            tags.append("deactivated")
        elif unconfirmed:
            severity = "low"
            tags.append("unconfirmed")
        elif member_type == "admin":
            severity = "medium"
            tags.append("org_admin")

        resources.append({
            "type": "trello.org_member",
            "id": f"org_member:{org_id}:{member_id}",
            "attributes": {
                "org_id": org_id, "member_id": member_id,
                "username": member.get("username"), "full_name": member.get("fullName"),
                "member_type": member_type, "unconfirmed": unconfirmed, "deactivated": deactivated,
                "last_active": entry.get("lastActive"),
            },
            "severity": severity,
            "tags": tags,
        })
    return resources


def _fetch_member_last_active(auth_params, member_id, cache, errors):
    """dateLastActive is only exposed via the single-member endpoint - the
    batched board/org memberships listings don't return it even when
    requested via member_fields (confirmed live). Cached per member_id so a
    member on N boards is only fetched once per scan, not once per board."""
    if member_id in cache:
        return cache[member_id]
    resp = requests.get(f"{API_BASE}/members/{member_id}", params={**auth_params, "fields": "dateLastActive"}, timeout=30)
    if resp.status_code != 200:
        errors.append({"check": f"trello_member_last_active:{member_id}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
        cache[member_id] = None
        return None
    last_active = resp.json().get("dateLastActive")
    cache[member_id] = last_active
    return last_active


def scan_board_members(auth_params, board_id, last_active_cache, errors):
    resources = []
    resp = requests.get(
        f"{API_BASE}/boards/{board_id}/memberships",
        params={**auth_params, "member": "true", "member_fields": "fullName,username"},
        timeout=30,
    )
    if resp.status_code != 200:
        errors.append({"check": f"trello_board_members:{board_id}", "reason": f"HTTP_{resp.status_code}", "detail": resp.text[:300]})
        return resources

    for membership in resp.json():
        member = membership.get("member") or {}
        member_id = membership.get("idMember", member.get("id", "unknown"))
        membership_type = membership.get("memberType")
        resources.append({
            "type": "trello.board_member",
            "id": f"board_member:{board_id}:{member_id}",
            "attributes": {
                "board_id": board_id, "member_id": member_id,
                "username": member.get("username"), "full_name": member.get("fullName"),
                "membership_type": membership_type,
                "last_active": _fetch_member_last_active(auth_params, member_id, last_active_cache, errors),
            },
            "severity": "medium" if membership_type == "admin" else "info",
            "tags": ["trello", "board_member"],
        })
    return resources


def scan(config, errors):
    """Returns (resources, status, message). message is only set for the
    'skipped' status."""
    creds_path = config["trello"]["_creds_path_resolved"]
    if not os.path.exists(creds_path):
        message = (
            f"Trello credentials not configured at {creds_path} - skipping. "
            "See references/trello_setup.md for how to generate a read-scoped token."
        )
        return [], "skipped", message

    try:
        with open(creds_path, "r", encoding="utf-8") as f:
            creds = json.load(f)
        api_key, token = creds["api_key"], creds["token"]
    except (OSError, json.JSONDecodeError, KeyError) as e:
        errors.append({"check": "trello_auth", "reason": "INVALID_CREDENTIALS_FILE", "detail": str(e)})
        return [], "error", None

    register_secret(api_key)
    register_secret(token)
    auth_params = {"key": api_key, "token": token}

    resources = []
    org_ids = config["trello"].get("organizations") or discover_organizations(auth_params, errors)
    last_active_cache = {}

    for org_id in org_ids:
        resources += scan_org_members(auth_params, org_id, errors)

        for board in list_boards(auth_params, org_id, errors):
            board_id = board["id"]
            visibility = (board.get("prefs") or {}).get("permissionLevel")
            resources.append({
                "type": "trello.board",
                "id": f"board:{board_id}",
                "attributes": {
                    "board_id": board_id, "name": board.get("name"), "closed": board.get("closed"),
                    "visibility": visibility, "date_last_activity": board.get("dateLastActivity"),
                },
                "severity": "high" if visibility == "public" else "info",
                "tags": ["trello", "board"],
            })
            resources += scan_board_members(auth_params, board_id, last_active_cache, errors)

    status = "ok" if not errors else "partial"
    return resources, status, None
