#!/usr/bin/env python
"""Pre-flight probe: reports which GCP checks the configured service account
can actually perform. Run this before the first `--scope gcp`/`--scope all`
scan so missing permissions or disabled APIs show up as a clear table instead
of a crash mid-scan.
"""
import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.config import load_config
from common.redact import register_secret, safe_print

import google.auth.transport.requests as google_auth_transport_requests
import requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# The .read-only scope variant rejects some IAM/Compute read methods outright
# (ACCESS_TOKEN_SCOPE_INSUFFICIENT) even when the underlying IAM role is
# read-only. OAuth scope is only a ceiling; the actual security boundary is
# the service account's IAM roles (see references/gcp_setup.md), so the full
# cloud-platform scope is used here deliberately.
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

CORE_PERMISSIONS = [
    "iam.serviceAccounts.list",
    "iam.serviceAccountKeys.list",
    "resourcemanager.projects.getIamPolicy",
    "compute.firewalls.list",
    "compute.instances.list",
    "compute.projects.get",
]


def _credentials(key_path):
    with open(key_path, "r", encoding="utf-8") as f:
        register_secret(f.read())
    return service_account.Credentials.from_service_account_file(key_path, scopes=SCOPES)


def check_core_permissions(creds, project_id):
    service = build("cloudresourcemanager", "v3", credentials=creds, cache_discovery=False)
    resp = service.projects().testIamPermissions(
        resource=f"projects/{project_id}", body={"permissions": CORE_PERMISSIONS}
    ).execute()
    granted = set(resp.get("permissions", []))
    return {p: (p in granted) for p in CORE_PERMISSIONS}


def _probe(build_fn, description):
    try:
        build_fn()
        return "ok", None
    except HttpError as e:
        status = getattr(getattr(e, "resp", None), "status", None)
        if status == 403:
            return "no_permission", str(e)
        if status == 404:
            return "not_enabled_or_not_found", str(e)
        if status == 400:
            return "needs_org_scoped_parent", str(e)
        return "error", str(e)
    except Exception as e:  # noqa: BLE001 - best-effort probe, never crash
        return "error", str(e)


def check_scc(creds, project_id):
    # SCC v2's project-scoped findings.list isn't exposed via the discovery
    # client (v1's project-scoped path is retired; v1's org-scoped path
    # needs an org-level role) - call the v2 REST API directly instead.
    if not creds.valid or creds.expired:
        creds.refresh(google_auth_transport_requests.Request())
    try:
        resp = requests.get(
            f"https://securitycenter.googleapis.com/v2/projects/{project_id}/sources/-/findings",
            headers={"Authorization": f"Bearer {creds.token}"},
            params={"pageSize": 1, "filter": 'state="ACTIVE"'},
            timeout=30,
        )
    except requests.RequestException as e:
        return "error", str(e)
    if resp.status_code == 200:
        return "ok", None
    if resp.status_code == 403:
        return "no_permission", resp.text[:300]
    if resp.status_code == 404:
        return "not_enabled_or_not_found", resp.text[:300]
    return "error", f"HTTP {resp.status_code}: {resp.text[:300]}"


def check_recommender(creds, project_id):
    def call():
        service = build("recommender", "v1", credentials=creds, cache_discovery=False)
        parent = f"projects/{project_id}/locations/global/recommenders/google.iam.policy.Recommender"
        service.projects().locations().recommenders().recommendations().list(parent=parent, pageSize=1).execute()

    return _probe(call, "IAM Recommender")


def check_monitoring(creds, project_id):
    def call():
        service = build("monitoring", "v3", credentials=creds, cache_discovery=False)
        end = datetime.datetime.now(datetime.timezone.utc)
        start = end - datetime.timedelta(minutes=1)
        service.projects().timeSeries().list(
            name=f"projects/{project_id}",
            filter='metric.type="iam.googleapis.com/service_account/authn_events_count"',
            interval_startTime=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            interval_endTime=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ).execute()

    return _probe(call, "Cloud Monitoring (service account usage metrics)")


def main():
    parser = argparse.ArgumentParser(description="Probe GCP permissions for the SOC2 scanner service account.")
    parser.add_argument("--config", default=None, help="Path to soc2.config.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    key_path = config["gcp"]["_key_path_resolved"]
    if not os.path.exists(key_path):
        safe_print(f"GCP service account key not found at {key_path}")
        sys.exit(1)

    project_ids = config.get("gcp", {}).get("project_ids") or []
    if not project_ids:
        with open(key_path, "r", encoding="utf-8") as f:
            project_ids = [json.load(f)["project_id"]]

    creds = _credentials(key_path)

    for project_id in project_ids:
        safe_print(f"\n=== GCP permission check: project {project_id} ===")
        try:
            core = check_core_permissions(creds, project_id)
        except HttpError as e:
            safe_print(f"  ERROR calling testIamPermissions: {e}")
            core = {p: False for p in CORE_PERMISSIONS}

        for perm, ok in core.items():
            safe_print(f"  [{'OK     ' if ok else 'MISSING'}] {perm}")

        scc_status, scc_detail = check_scc(creds, project_id)
        safe_print(f"  [{scc_status.upper():^22}] Security Command Center findings" + (f" ({scc_detail})" if scc_detail else ""))

        rec_status, rec_detail = check_recommender(creds, project_id)
        safe_print(f"  [{rec_status.upper():^22}] IAM Recommender" + (f" ({rec_detail})" if rec_detail else ""))

        mon_status, mon_detail = check_monitoring(creds, project_id)
        safe_print(f"  [{mon_status.upper():^22}] Cloud Monitoring (service account usage metrics)" + (f" ({mon_detail})" if mon_detail else ""))

    safe_print(
        "\nDone. Missing permissions/disabled APIs are skipped gracefully during scans "
        "(see references/gcp_setup.md for how to grant them)."
    )


if __name__ == "__main__":
    main()
