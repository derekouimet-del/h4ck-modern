"""http_scan module — HTTP status/header scanner."""

from __future__ import annotations

import asyncio
from typing import Iterable

import httpx

from .output import Finding, Reporter
from .scope import ScopeError, validate_targets


async def http_scan(
    targets: Iterable[str],
    *,
    concurrency: int = 50,
    timeout: float = 10.0,
    allow_public: bool = False,
    reporter: Reporter | None = None,
) -> list[dict]:
    """HTTP GET against *targets*, reporting status, headers, and body size."""
    from urllib.parse import urlparse

    host_list = validate_targets(targets, allow_public=allow_public)
    urls: list[str] = []
    for h in host_list:
        if urlparse(h).scheme:
            urls.append(h)
        else:
            urls.append(f"http://{h}")
            urls.append(f"https://{h}")

    semaphore = asyncio.Semaphore(concurrency)
    results: list[dict] = []

    async with httpx.AsyncClient(
        headers={"User-Agent": "h4ck-modern/0.1"}, verify=True, timeout=timeout
    ) as client:

        async def fetch(url):
            async with semaphore:
                try:
                    r = await client.get(url, follow_redirects=True)
                    return {
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "server": r.headers.get("server"),
                        "content_type": r.headers.get("content-type"),
                        "final_url": str(r.url),
                    }
                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    return {"url": url, "error": str(exc)}

        responses = await asyncio.gather(*[fetch(u) for u in urls])

    for res in responses:
        results.append(res)
        if reporter is not None and "error" not in res:
            reporter.add(
                Finding(
                    category="http-scan",
                    target=res["url"],
                    detail=f"HTTP {res['status']} size={res['size']} server={res['server']}",
                    status=res["status"],
                )
            )

    results.sort(key=lambda r: r.get("url", ""))
    return results
