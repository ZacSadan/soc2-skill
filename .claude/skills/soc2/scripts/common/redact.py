"""Secret-scrubbing helpers.

Every secret literal loaded at runtime (API tokens, service-account private
keys, Trello key/token) must be registered here immediately after being read
from disk. strip_secrets()/safe_print() then strip those literals from any
text before it reaches the console or a file, as defense in depth against
secrets leaking via error messages or tracebacks.
"""
import builtins

_SECRETS = set()


def register_secret(value):
    if not value:
        return
    value = value.strip()
    if len(value) >= 6:  # avoid registering trivial/empty strings that would over-redact
        _SECRETS.add(value)


def strip_secrets(text):
    if not isinstance(text, str):
        return text
    for secret in _SECRETS:
        if secret and secret in text:
            text = text.replace(secret, "***REDACTED***")
    return text


def safe_print(*args, **kwargs):
    cleaned = [strip_secrets(str(a)) for a in args]
    builtins.print(*cleaned, **kwargs)
