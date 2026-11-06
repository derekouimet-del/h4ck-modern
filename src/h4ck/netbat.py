"""Async TCP port scanner — modern replacement for netbat / port_scanner."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Iterable

from .output import Finding, Reporter
from .scope import ScopeError, validate_targets
from .utils import expand_hosts, parse_ports


@dataclass
class PortResult:
    host: str
    port: int
    open: bool
    latency_ms: float | None = None


async def _probe_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> PortResult:
    start = time.perf_counter()
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            latency = (time.perf_counter() - start) * 1000
            return PortResult(host, port, True, latency)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return PortResult(host, port, False, None)


async def scan_ports(
    targets: Iterable[str],
    ports: str,
    *,
    concurrency: int = 200,
    timeout: float = 2.0,
    allow_public: bool = False,
    allow_random: bool = False,
    reporter: Reporter | None = None,
    verbose: bool = False,
) -> list[PortResult]:
    host_list = validate_targets(
        targets, allow_public=allow_public, allow_random=allow_random
    )
    host_list = expand_hosts(host_list)
    port_list = parse_ports(ports)

    semaphore = asyncio.Semaphore(concurrency)
    results: list[PortResult] = []

    tasks = [
        _probe_port(host, port, timeout, semaphore)
        for host in host_list
        for port in port_list
    ]

    for coro in asyncio.as_completed(tasks):
        res = await coro
        results.append(res)
        if reporter is not None:
            if res.open:
                reporter.add(
                    Finding(
                        category="open-port",
                        target=res.host,
                        detail=f"open ({res.latency_ms:.0f} ms)"
                        if res.latency_ms is not None
                        else "open",
                        port=res.port,
                    )
                )
            elif verbose:
                reporter.add(
                    Finding(
                        category="closed-port",
                        target=res.host,
                        detail="closed",
                        port=res.port,
                    )
                )

    results.sort(key=lambda r: (r.host, r.port))
    return results
