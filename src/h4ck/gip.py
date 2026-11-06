"""gip module — get public IP address."""

from __future__ import annotations

import httpx


def get_public_ip(timeout: float = 10.0) -> str:
    """Fetch the public IP address of the machine running h4ck-modern."""
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://icanhazip.com",
    ]
    last_error: str | None = None
    for svc in services:
        try:
            r = httpx.get(svc, timeout=timeout)
            r.raise_for_status()
            return r.text.strip()
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
    if last_error:
        raise RuntimeError(f"Could not determine public IP: {last_error}")
    raise RuntimeError("Could not determine public IP")
