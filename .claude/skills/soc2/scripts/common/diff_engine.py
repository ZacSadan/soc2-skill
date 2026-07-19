"""Generic, provider-agnostic snapshot diff engine.

Every provider snapshot is a flat list of Resource dicts, so one diff
implementation works uniformly across GCP/Bitbucket/Trello.
"""
from .schema import watched_fields


def diff_snapshots(previous, current):
    """previous: dict form of a prior Snapshot, or None if there isn't one.
    current: dict form of the just-completed Snapshot.

    Returns {"baseline": bool, "added": [...], "removed": [...], "modified": [...]}.
    """
    if not previous:
        return {"baseline": True, "added": [], "removed": [], "modified": []}

    prev_by_key = {(r["type"], r["id"]): r for r in previous.get("resources", [])}
    curr_by_key = {(r["type"], r["id"]): r for r in current.get("resources", [])}

    prev_keys = set(prev_by_key)
    curr_keys = set(curr_by_key)

    added = [curr_by_key[k] for k in sorted(curr_keys - prev_keys, key=str)]
    removed = [prev_by_key[k] for k in sorted(prev_keys - curr_keys, key=str)]

    modified = []
    for k in sorted(curr_keys & prev_keys, key=str):
        prev_r, curr_r = prev_by_key[k], curr_by_key[k]
        watch = watched_fields(k[0])
        prev_attrs, curr_attrs = prev_r.get("attributes", {}), curr_r.get("attributes", {})
        fields_to_check = (set(prev_attrs) | set(curr_attrs)) if watch == "*" else set(watch)

        field_changes = {}
        for field_name in sorted(fields_to_check):
            before, after = prev_attrs.get(field_name), curr_attrs.get(field_name)
            if before != after:
                field_changes[field_name] = {"before": before, "after": after}

        if field_changes:
            modified.append({
                "type": k[0],
                "id": k[1],
                "severity": curr_r.get("severity", "info"),
                "field_changes": field_changes,
                "attributes": curr_attrs,
            })

    return {"baseline": False, "added": added, "removed": removed, "modified": modified}
