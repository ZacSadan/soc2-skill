# Snapshot Schema and Diff Algorithm

## Snapshot envelope

One JSON file per **provider** per run, written to `.state/snapshots/<provider>/<provider>-<run_id>.json`, even during a `--scope all` run (which runs all five scanners under one `run_id` but still writes five independent files). This keeps "the latest previous snapshot for provider X" well-defined regardless of what `--scope` produced either snapshot — no scope-compatibility matrix needed.

```json
{
  "schema_version": 1,
  "provider": "gcp",
  "run_id": "20260706T143000Z-a1b2c3",
  "started_at": "2026-07-06T14:30:00+00:00",
  "finished_at": "2026-07-06T14:30:42+00:00",
  "target": {"project_ids": ["your-gcp-project-id"]},
  "status": "ok",
  "errors": [{"check": "iam_recommender", "reason": "SERVICE_DISABLED_OR_NOT_FOUND", "detail": "..."}],
  "resources": [
    {
      "type": "gcp.compute.firewall_rule",
      "id": "fw:default-allow-ssh",
      "attributes": {"name": "default-allow-ssh", "source_ranges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
      "severity": "critical",
      "tags": ["network", "firewall", "public-exposure"]
    }
  ]
}
```

`status` is one of `ok` (no errors), `partial` (some checks failed but others succeeded), `skipped` (provider has no credentials configured — Trello only), or `error` (nothing could run, e.g. auth failure).

## Resource identity

Every resource has a `type` (`"<provider>.<kind>"`) and a stable `id` string built by the scanner from that resource's identity fields (e.g. `sa_key:<email>:<key_id>`, `fw:<name>`, `board_member:<board_id>:<member_id>`). The diff engine matches resources across runs purely by `(type, id)` — see `.claude/skills/soc2/scripts/common/schema.py` for the full type list and which attributes are "watched" for change detection per type.

## Diff algorithm (`common/diff_engine.py`)

1. No previous snapshot found or it fails to parse → `{"baseline": true}`, empty added/removed/modified — never an error.
2. Index both snapshots by `(type, id)`.
3. `added` = ids present only in the current snapshot.
4. `removed` = ids present only in the previous snapshot.
5. `modified` = ids present in both where a *watched* attribute differs (`"*"` in the type registry means all attributes are compared; otherwise only the listed fields) — each entry lists per-field `{before, after}`.
6. Unchanged resources are dropped from the diff entirely.

Snapshot retention is controlled by `output.snapshot_retention_count` (default 20) — older snapshots for a provider are pruned after each run.
