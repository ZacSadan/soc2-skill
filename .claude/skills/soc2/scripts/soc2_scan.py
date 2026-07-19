#!/usr/bin/env python
"""SOC2 scanner CLI entrypoint.

Runs the GCP / Bitbucket / Trello / AWS scanners (selectively or all), diffs
each provider's result against its own previous snapshot, and renders a
console summary plus a Markdown report.
"""
import argparse
import datetime
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.config import load_config
from common.diff_engine import diff_snapshots
from common.redact import safe_print, strip_secrets
from common.report_writer import render_console, render_markdown
from common.snapshot_store import latest_snapshot, prune_old_snapshots, write_snapshot

ALL_PROVIDERS = ["gcp", "bitbucket", "trello", "aws", "gsuite", "confluence"]
RUN_ORDER = ["bitbucket", "gcp", "trello", "aws", "gsuite", "confluence"]


def _run_id():
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}-{uuid.uuid4().hex[:6]}"


def _timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _make_snapshot(provider, run_id, started_at, target, status, resources, errors):
    return {
        "schema_version": 1,
        "provider": provider,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": _timestamp(),
        "target": target,
        "status": status,
        "errors": errors,
        "resources": resources,
    }


def run_gcp(config, run_id):
    from providers import gcp_scanner

    started_at = _timestamp()
    project_ids = config["gcp"].get("project_ids") or []
    if not project_ids:
        with open(config["gcp"]["_key_path_resolved"], "r", encoding="utf-8") as f:
            project_ids = [json.load(f)["project_id"]]

    errors = []
    resources = []
    for project_id in project_ids:
        resources += gcp_scanner.scan(config, project_id, config["gcp"].get("checks", {}), errors)

    status = "ok" if not errors else "partial"
    return _make_snapshot("gcp", run_id, started_at, {"project_ids": project_ids}, status, resources, errors)


def run_bitbucket(config, run_id):
    from providers import bitbucket_scanner

    started_at = _timestamp()
    errors = []
    resources, status = bitbucket_scanner.scan(config, errors)
    target = {"workspaces": config["bitbucket"].get("workspaces") or "auto"}
    return _make_snapshot("bitbucket", run_id, started_at, target, status, resources, errors)


def run_trello(config, run_id):
    from providers import trello_scanner

    started_at = _timestamp()
    errors = []
    resources, status, message = trello_scanner.scan(config, errors)
    if status == "skipped" and message:
        safe_print(message)
    return _make_snapshot("trello", run_id, started_at, {}, status, resources, errors)


def run_aws(config, run_id):
    from providers import aws_scanner

    started_at = _timestamp()
    errors = []
    resources, status = aws_scanner.scan(config, errors)
    target = {"regions": config["aws"].get("regions") or []}  # empty = every region enabled for the account
    return _make_snapshot("aws", run_id, started_at, target, status, resources, errors)


def run_gsuite(config, run_id):
    from providers import gsuite_scanner

    started_at = _timestamp()
    errors = []
    resources, status, message = gsuite_scanner.scan(config, errors)
    if status == "skipped" and message:
        safe_print(message)
    return _make_snapshot("gsuite", run_id, started_at, {}, status, resources, errors)


def run_confluence(config, run_id):
    from providers import confluence_scanner

    started_at = _timestamp()
    errors = []
    resources, status, message = confluence_scanner.scan(config, errors)
    if status == "skipped" and message:
        safe_print(message)
    return _make_snapshot("confluence", run_id, started_at, {}, status, resources, errors)


RUNNERS = {
    "gcp": run_gcp, "bitbucket": run_bitbucket, "trello": run_trello, "aws": run_aws,
    "gsuite": run_gsuite, "confluence": run_confluence,
}


def main():
    parser = argparse.ArgumentParser(description="SOC2 security/compliance scanner.")
    parser.add_argument("--scope", choices=["all"] + ALL_PROVIDERS, default="all")
    parser.add_argument("--config", default=None, help="Path to soc2.config.yaml")
    parser.add_argument("--no-diff", action="store_true", help="Skip diffing against the previous snapshot")
    parser.add_argument("--no-report", action="store_true", help="Skip writing the Markdown report")
    parser.add_argument("--json-only", action="store_true", help="Write snapshots only; skip console/Markdown rendering")
    args = parser.parse_args()

    config = load_config(args.config)
    run_id = _run_id()

    requested = set(ALL_PROVIDERS if args.scope == "all" else [args.scope])
    results = {}
    snapshot_paths = {}

    for provider in [p for p in RUN_ORDER if p in requested]:
        if not config.get(provider, {}).get("enabled", True):
            continue

        snapshot = RUNNERS[provider](config, run_id)

        state_dir = config["output"]["_state_dir_resolved"]
        snap_path = write_snapshot(state_dir, provider, snapshot)
        snapshot_paths[provider] = snap_path
        prune_old_snapshots(state_dir, provider, config["output"].get("snapshot_retention_count", 20))

        if args.no_diff:
            diff = {"baseline": True, "added": [], "removed": [], "modified": []}
        else:
            previous = latest_snapshot(state_dir, provider, exclude_path=snap_path)
            diff = diff_snapshots(previous, snapshot)

        results[provider] = {"snapshot": snapshot, "diff": diff}

    if not args.json_only:
        render_console(results, config)

    exit_code = 0
    for r in results.values():
        for res in r["snapshot"].get("resources", []):
            if res.get("severity") in ("critical", "high"):
                exit_code = 1

    if not args.json_only and not args.no_report:
        reports_dir = config["output"]["_reports_dir_resolved"]
        os.makedirs(reports_dir, exist_ok=True)
        md = render_markdown(results, config, args.scope, run_id, _timestamp(), snapshot_paths)
        md = strip_secrets(md)
        report_path = os.path.join(reports_dir, f"soc2-report-{args.scope}-{run_id}.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(md)
        safe_print(f"\nReport written to: {report_path}")

    safe_print(f"Snapshots written: {snapshot_paths}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
