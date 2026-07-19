"""Read/write timestamped JSON snapshots, one file per provider per run."""
import glob
import json
import os

from .redact import strip_secrets


def _provider_dir(state_dir, provider):
    d = os.path.join(state_dir, "snapshots", provider)
    os.makedirs(d, exist_ok=True)
    return d


def _list_snapshot_files(state_dir, provider):
    d = _provider_dir(state_dir, provider)
    return sorted(glob.glob(os.path.join(d, f"{provider}-*.json")))


def write_snapshot(state_dir, provider, snapshot_dict):
    d = _provider_dir(state_dir, provider)
    path = os.path.join(d, f"{provider}-{snapshot_dict['run_id']}.json")
    text = json.dumps(snapshot_dict, indent=2, sort_keys=True)
    text = strip_secrets(text)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def latest_snapshot(state_dir, provider, exclude_path=None):
    files = [f for f in _list_snapshot_files(state_dir, provider) if f != exclude_path]
    if not files:
        return None
    try:
        with open(files[-1], "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def prune_old_snapshots(state_dir, provider, keep):
    files = _list_snapshot_files(state_dir, provider)
    if len(files) <= keep:
        return
    for f in files[:-keep]:
        try:
            os.remove(f)
        except OSError:
            pass
