"""WHOIS module — modern replacement for whois.py."""

from __future__ import annotations

import socket
from typing import Optional


def whois_lookup(
    target: str,
    *,
    port: int = 43,
    timeout: float = 10.0,
) -> str:
    """Perform a raw WHOIS lookup against the IANA WHOIS server.

    Returns the raw WHOIS response text for *target* (domain or IP).
    """
    # For IP addresses, query the appropriate RIR via IANA.
    query = target
    try:
        with socket.create_connection(("whois.iana.org", port), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        return f"WHOIS lookup failed: {exc}"

    text = data.decode(errors="ignore")

    # If a referral server is found (whois.iana.org returns one for IPs/TLDs),
    # follow it once.
    referral: Optional[str] = None
    for line in text.splitlines():
        if "refer:" in line.lower() or "whois:" in line.lower():
            parts = line.split()
            if len(parts) >= 2:
                referral = parts[-1]
                break

    if referral:
        try:
            with socket.create_connection((referral, port), timeout=timeout) as s:
                s.sendall((query + "\r\n").encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            text = data.decode(errors="ignore")
        except OSError as exc:
            text += f"\n[Follow-up to {referral} failed: {exc}]"

    return text
