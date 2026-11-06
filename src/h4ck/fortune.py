"""Fortune module — random-IP scanning / generation (fortune*, fortune_rtsp, fortune_port, fortune_http_cam, fortune_vuln, fortune_ftp_img, fortune_http_unseen).

DANGER: This scans randomly generated public IP addresses on the internet.
Only enable with --random-internet and only against systems you own or have
written authorization to test. Requires explicit interactive confirmation.
"""

from __future__ import annotations

import asyncio
from typing import Iterable

import httpx

from .netbat import scan_ports
from .output import Finding, Reporter
from .scope import ScopeError, validate_targets
from .utils import generate_random_public_ips


async def _http_probe(ip: str, port: int, scheme: str, semaphore: asyncio.Semaphore):
    url = f"{scheme}://{ip}:{port}/"
    async with semaphore:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                r = await client.get(url)
                return r.status_code, len(r.content), r.headers.get("server", "")
        except Exception:  # noqa: BLE001
            return None


async def fortune_scan(
    count: int = 100,
    *,
    ports: str = "80,443,554,8080",
    randomize: bool = True,
    seed: int | None = None,
    allow_random: bool = False,
    reporter: Reporter | None = None,
) -> list[dict]:
    """Scan *count* random public IPs for open ports/services.

    Requires allow_random=True (set via --random-internet).
    """
    if not allow_random:
        raise ScopeError(
            "Random internet scanning is disabled by default. Pass "
            "--random-internet and confirm before scanning random public IPs."
        )

    ips = generate_random_public_ips(count, seed=seed)
    results = await scan_ports(
        ips,
        ports,
        concurrency=200,
        timeout=2.0,
        allow_public=True,
        allow_random=True,
        reporter=reporter,
    )

    out: list[dict] = []
    for r in results:
        if r.open:
            out.append(
                {
                    "ip": r.host,
                    "port": r.port,
                    "latency_ms": r.latency_ms,
                }
            )
            if reporter is not None:
                reporter.add(
                    Finding(
                        category="fortune-open-port",
                        target=r.host,
                        detail=f"open ({r.latency_ms:.0f} ms)"
                        if r.latency_ms
                        else "open",
                        port=r.port,
                    )
                )
    return out


async def fortune_http_cam(
    count: int = 50,
    *,
    allow_random: bool = False,
    reporter: Reporter | None = None,
) -> list[dict]:
    """Probe random IPs for exposed HTTP camera/web interfaces (fortune_http_cam)."""
    if not allow_random:
        raise ScopeError("Random internet scanning requires --random-internet.")

    ips = generate_random_public_ips(count)
    semaphore = asyncio.Semaphore(100)
    results: list[dict] = []

    async def probe(ip):
        status = await _http_probe(ip, 80, "http", semaphore)
        if status and status[0] == 200:
            return {"ip": ip, "port": 80, "status": status[0], "size": status[1], "server": status[2]}
        status = await _http_probe(ip, 8080, "http", semaphore)
        if status and status[0] == 200:
            return {"ip": ip, "port": 8080, "status": status[0], "size": status[1], "server": status[2]}
        return None

    for coro in asyncio.as_completed([probe(ip) for ip in ips]):
        res = await coro
        if res:
            results.append(res)
            if reporter is not None:
                reporter.add(
                    Finding(
                        category="fortune-http-cam",
                        target=res["ip"],
                        detail=f"HTTP {res['status']} size={res['size']} server={res['server']}",
                        port=res["port"],
                    )
                )
    return results


async def fortune_rtsp(
    count: int = 50,
    *,
    allow_random: bool = False,
    reporter: Reporter | None = None,
) -> list[dict]:
    """Probe random IPs for open RTSP port 554 (fortune_rtsp)."""
    if not allow_random:
        raise ScopeError("Random internet scanning requires --random-internet.")

    ips = generate_random_public_ips(count)
    results = await scan_ports(
        ips,
        "554",
        concurrency=200,
        timeout=2.0,
        allow_public=True,
        allow_random=True,
        reporter=reporter,
    )
    out = [
        {"ip": r.host, "port": r.port, "latency_ms": r.latency_ms}
        for r in results
        if r.open
    ]
    if reporter is not None:
        for r in out:
            reporter.add(
                Finding(
                    category="fortune-rtsp",
                    target=r["ip"],
                    detail="RTSP port 554 open",
                    port=r["port"],
                )
            )
    return out
