"""RTSP module — rtsp_brute, rtsp_capture, fortune_rtsp.

DANGER: Credential brute-forcing against third-party devices is illegal in most
jurisdictions. The brute-force path requires --authorize-brute and a user
supplied wordlist; it only tests connectivity/auth against hosts you explicitly
name. No password dictionary is bundled.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .output import Finding, Reporter
from .scope import ScopeError, validate_targets


RTSP_OPTIONS = (
    b"OPTIONS rtsp://%s:%d/ RTSP/1.0\r\n"
    b"CSeq: 1\r\n"
    b"User-Agent: h4ck-modern/0.1\r\n"
    b"\r\n"
)


@dataclass
class RTSPResult:
    host: str
    port: int
    reachable: bool
    authed: bool = False


async def _rtsp_options(host: str, port: int, timeout: float = 5.0) -> bool:
    """Return True if an RTSP server responds to OPTIONS."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(RTSP_OPTIONS % (host.encode(), port))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return b"RTSP/1.0" in data or b"RTSP/" in data
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def _rtsp_try_creds(
    host: str, port: int, user: str, password: str, timeout: float = 5.0
) -> bool:
    """Attempt a single RTSP DESCRIBE with basic auth. Returns True on success."""
    import base64

    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = (
        b"DESCRIBE rtsp://%s:%d/ RTSP/1.0\r\n"
        b"CSeq: 2\r\n"
        b"Authorization: Basic %s\r\n"
        b"User-Agent: h4ck-modern/0.1\r\n"
        b"\r\n"
    ) % (host.encode(), port, auth.encode())
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(req)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return b"200 OK" in data or b"RTSP/1.0 200" in data
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def rtsp_brute(
    targets: Iterable[str],
    *,
    port: int = 554,
    wordlist: Path | None = None,
    authorize_brute: bool = False,
    concurrency: int = 50,
    reporter: Reporter | None = None,
) -> list[dict]:
    """Brute-force RTSP authentication on *targets*.

    Requires --authorize-brute and --wordlist. Only scan hosts you own or have
    written authorization to test. No wordlist is bundled — supply your own.
    """
    if not authorize_brute:
        raise ScopeError(
            "RTSP brute-forcing is disabled by default. Pass "
            "--authorize-brute only for systems you own or have written "
            "authorization to test."
        )
    if wordlist is None:
        raise ScopeError("--wordlist is required for RTSP brute-forcing.")
    if not wordlist.exists():
        raise ScopeError(f"Wordlist not found: {wordlist}")

    host_list = validate_targets(targets, allow_public=True)
    creds: list[tuple[str, str]] = []
    for line in wordlist.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            u, p = line.split(":", 1)
            creds.append((u, p))
        else:
            creds.append((line, line))

    if not creds:
        raise ScopeError("Wordlist contains no credentials.")

    results: list[dict] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def try_host(host):
        reachable = await _rtsp_options(host, port)
        if not reachable:
            return
        entry = {"host": host, "port": port, "reachable": True, "credentials": []}
        for user, pwd in creds:
            if await _rtsp_try_creds(host, port, user, pwd):
                entry["credentials"].append({"user": user, "password": pwd})
                if reporter is not None:
                    reporter.add(
                        Finding(
                            category="rtsp-brute-hit",
                            target=host,
                            detail=f"RTSP creds {user}:{pwd}",
                            port=port,
                        )
                    )
        results.append(entry)

    await asyncio.gather(*[try_host(h) for h in host_list])
    return results


async def rtsp_capture(
    targets: Iterable[str],
    *,
    port: int = 554,
    output_dir: Path | None = None,
    reporter: Reporter | None = None,
) -> list[dict]:
    """Probe RTSP targets and report reachable streams (rtsp_capture).

    Does not download or store media by default — only reports whether an RTSP
    stream is reachable. Pass --output-dir to save session snapshots (metadata
    only; actual media capture left to the operator).
    """
    host_list = validate_targets(targets, allow_public=True)
    results: list[dict] = []

    for host in host_list:
        reachable = await _rtsp_options(host, port)
        entry = {"host": host, "port": port, "reachable": reachable}
        results.append(entry)
        if reachable and reporter is not None:
            reporter.add(
                Finding(
                    category="rtsp-capture",
                    target=host,
                    detail="RTSP stream reachable",
                    port=port,
                )
            )
    return results
