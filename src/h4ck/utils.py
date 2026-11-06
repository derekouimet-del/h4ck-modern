"""Shared helpers."""

from __future__ import annotations

import ipaddress
import random
import re
from typing import Iterable

_PORT_RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def parse_ports(ports: str) -> list[int]:
    """Parse ``22,80,443,8000-9000`` into a sorted list of ints."""
    result: set[int] = set()
    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue
        m = _PORT_RANGE_RE.match(part)
        if not m:
            raise ValueError(f"Invalid port spec: {part!r}")
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        if not (1 <= start <= 65535) or not (1 <= end <= 65535):
            raise ValueError(f"Port out of range: {part!r}")
        if end < start:
            raise ValueError(f"Invalid range (end < start): {part!r}")
        result.update(range(start, end + 1))
    return sorted(result)


def expand_hosts(hosts: list[str]) -> list[str]:
    """Expand CIDR entries into individual IP strings."""
    expanded: list[str] = []
    for h in hosts:
        if "/" in h:
            net = ipaddress.ip_network(h, strict=False)
            expanded.extend(str(host) for host in net.hosts())
        else:
            expanded.append(h)
    return expanded


def generate_random_public_ips(count: int, seed: int | None = None) -> list[str]:
    """Generate *count* random public (non-RFC1918) IPv4 addresses."""
    rng = random.Random(seed)
    ips: list[str] = []
    while len(ips) < count:
        octets = [rng.randint(0, 255) for _ in range(4)]
        ip = ipaddress.IPv4Address(".".join(map(str, octets)))
        if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_multicast:
            continue
        ips.append(str(ip))
    return ips
