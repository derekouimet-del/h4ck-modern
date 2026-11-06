"""Scope / ethics controls.

h4ck-modern only scans targets you explicitly authorize by default. Higher-risk
features (random internet scanning, credential brute-forcing) require explicit
opt-in flags and are never enabled by accident.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable


class ScopeError(ValueError):
    """Raised when a target falls outside the authorized scope."""


def is_private_ip(host: str) -> bool:
    """Return True if *host* is a private/RFC1918 IP address."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # hostname — cannot classify without DNS
    return ip.is_private


def validate_targets(
    targets: Iterable[str],
    *,
    allow_public: bool = False,
    allow_random: bool = False,
) -> list[str]:
    """Validate and normalize targets.

    Parameters
    ----------
    targets:
        Hostnames, IPv4/IPv6 addresses, CIDR networks, or URLs.
    allow_public:
        Allow public (non-RFC1918) targets. Required for anything outside LAN.
    allow_random:
        Allow scanning randomly generated public IPs ("fortune" mode).
    """
    normalized: list[str] = []
    for target in targets:
        target = target.strip()
        if not target:
            continue

        # Strip scheme for host validation, keep original for URL targets.
        from urllib.parse import urlparse

        parsed = urlparse(target)
        host = parsed.hostname or target

        # CIDR network (no scheme)
        if not parsed.scheme and "/" in host:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError as exc:
                raise ScopeError(f"Invalid network '{host}': {exc}") from exc
            for h in net.hosts():
                hs = str(h)
                if not allow_public and not is_private_ip(hs):
                    raise ScopeError(
                        f"Public target '{hs}' is outside authorized scope. "
                        "Use --allow-public only for hosts you own or have "
                        "written authorization to test."
                    )
                normalized.append(hs)
            continue

        if not allow_public and not allow_random and not is_private_ip(host):
            # Public IP or unclassifiable hostname without opt-in.
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                pass  # hostname — user explicitly named it, allow
            else:
                if not ip.is_private:
                    raise ScopeError(
                        f"Public target '{target}' is outside authorized "
                        "scope. Pass --allow-public only for targets you own "
                        "or have written authorization to test."
                    )
        normalized.append(target)

    if not normalized:
        raise ScopeError("No valid targets provided.")

    return normalized


def confirm_random_internet() -> bool:
    """Prompt for explicit confirmation before random internet scanning."""
    import typer

    return typer.confirm(
        "You are about to scan randomly generated public IP addresses on the "
        "internet. Only do this against systems you own or have written "
        "authorization to test. Continue?",
        abort=False,
        default=False,
    )
