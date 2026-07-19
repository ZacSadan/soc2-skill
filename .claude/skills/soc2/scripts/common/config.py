"""Load and validate config/soc2.config.yaml, resolving all relative paths
(secrets, state dir, reports dir) against the repo root.

Also loads secrets/soc2.config.private.yaml, if present, and deep-merges it
on top - a gitignored file (living alongside the other credentials in
secrets/, not config/, since it holds company-identifying values) for
values that identify this specific company/workspace (Bitbucket workspace
slug, hardcoded manual-review URLs, firewall/bucket name-highlighting
patterns) rather than being generic scanner settings. The committed
soc2.config.yaml stays safe to make public; the private file is where
anything company-specific belongs.
"""
import os

import yaml


def _find_repo_root(start):
    d = start
    for _ in range(10):
        if os.path.isdir(os.path.join(d, ".claude")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    raise RuntimeError(f"Could not locate repo root (no .claude directory found above {start})")


def _deep_merge(base, override):
    """Recursively merges `override` onto `base`. Dicts are merged
    key-by-key; any other value (including lists) is replaced wholesale by
    the override's value rather than concatenated - a private
    `bitbucket.workspaces: [...]` list is meant to fully replace the public
    default, not append to it."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(config_path=None):
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = _find_repo_root(here)

    if config_path is None:
        config_path = os.path.join(repo_root, "config", "soc2.config.yaml")
    else:
        config_path = os.path.abspath(config_path)

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    private_path = os.path.join(repo_root, "secrets", "soc2.config.private.yaml")
    if os.path.exists(private_path):
        with open(private_path, "r", encoding="utf-8") as f:
            private_cfg = yaml.safe_load(f) or {}
        _deep_merge(cfg, private_cfg)
    cfg["_private_config_path"] = private_path if os.path.exists(private_path) else None

    def resolve(relpath):
        return os.path.normpath(os.path.join(repo_root, relpath))

    gcp = cfg.setdefault("gcp", {})
    gcp["_key_path_resolved"] = resolve(gcp.get("service_account_key_path", "secrets/gcp-service-account.json"))

    bitbucket = cfg.setdefault("bitbucket", {})
    bitbucket["_token_path_resolved"] = resolve(bitbucket.get("token_path", "secrets/bitbucket-token.txt"))
    # Only used for auth_mode: basic_email - a real person's identity, so it
    # lives in a gitignored secrets/ file rather than the committed config.
    # Shares the same file as gsuite's delegated admin email below (same
    # person, same underlying identity) rather than keeping two copies.
    bitbucket["_account_email_path_resolved"] = resolve(
        bitbucket.get("account_email_path", "secrets/delegated-admin-email.txt")
    )

    trello = cfg.setdefault("trello", {})
    trello["_creds_path_resolved"] = resolve(trello.get("credentials_path", "secrets/trello-credentials.json"))

    aws = cfg.setdefault("aws", {})
    aws["_creds_path_resolved"] = resolve(aws.get("credentials_path", "secrets/aws-access-keys.csv"))

    gsuite = cfg.setdefault("gsuite", {})
    gsuite["_key_path_resolved"] = resolve(gsuite.get("service_account_key_path", "secrets/gcp-service-account.json"))
    # The delegated admin's email is a real person's identity, not a
    # generic setting - kept out of the (committed) config file and read
    # from a gitignored secrets/ file instead, same treatment as every
    # other credential in this project. Shared with bitbucket above.
    gsuite["_delegated_admin_path_resolved"] = resolve(
        gsuite.get("delegated_admin_email_path", "secrets/delegated-admin-email.txt")
    )

    confluence = cfg.setdefault("confluence", {})
    confluence["_token_path_resolved"] = resolve(confluence.get("token_path", "secrets/id-atlassian-confluence-token.txt"))
    # Shares the same delegated-admin identity as bitbucket/gsuite above.
    confluence["_account_email_path_resolved"] = resolve(
        confluence.get("account_email_path", "secrets/delegated-admin-email.txt")
    )

    output = cfg.setdefault("output", {})
    output["_state_dir_resolved"] = resolve(output.get("state_dir", ".state"))
    output["_reports_dir_resolved"] = resolve(output.get("reports_dir", "reports"))

    cfg["_repo_root"] = repo_root
    cfg["_config_path"] = config_path
    return cfg
