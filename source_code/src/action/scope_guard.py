"""Hard scope enforcement. Every network-facing action MUST call check_scope()
before touching the target. This is the single safety belt of the whole agent:
no exceptions, no bypass flags.
"""

from urllib.parse import urlparse


class ScopeViolationError(Exception):
    """Raised when an action targets a host outside the configured allowlist."""


def _extract_host(url_or_host: str) -> str:
    """Accepts either a bare host ('localhost') or a full URL and returns the host."""
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        host = parsed.hostname
    else:
        # Could be "host:port" or a path-only string with no scheme.
        host = url_or_host.split("/")[0].split(":")[0]
    if not host:
        raise ScopeViolationError(f"Could not determine host from '{url_or_host}'")
    return host.lower()


def check_scope(url_or_host: str, allowlist: list[str]) -> str:
    """Validate that url_or_host resolves to a host in allowlist.

    Returns the extracted host on success. Raises ScopeViolationError otherwise.
    Comparison is exact (case-insensitive), no wildcard/subdomain matching, to
    avoid accidental scope creep.
    """
    host = _extract_host(url_or_host)
    normalized_allowlist = {h.lower() for h in allowlist}
    if host not in normalized_allowlist:
        raise ScopeViolationError(
            f"Target host '{host}' is outside the allowlist {sorted(normalized_allowlist)}. "
            "Action rejected."
        )
    return host


class ScopeGuard:
    """Thin stateful wrapper so action-layer modules can hold one guard instance
    configured once from config.yaml instead of threading the allowlist everywhere.
    """

    def __init__(self, allowlist: list[str], base_url: str | None = None):
        if not allowlist:
            raise ValueError("ScopeGuard requires a non-empty allowlist")
        self.allowlist = list(allowlist)
        self.base_url = base_url
        if base_url is not None:
            # Fail fast at construction time if the configured base_url itself
            # is not in scope -- a misconfigured allowlist should never load silently.
            check_scope(base_url, self.allowlist)

    def check(self, url_or_host: str) -> str:
        return check_scope(url_or_host, self.allowlist)

    def is_in_scope(self, url_or_host: str) -> bool:
        try:
            self.check(url_or_host)
            return True
        except ScopeViolationError:
            return False
