"""camposter module — POST data to a target (camposter)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Iterable

import httpx

from .output import Finding, Reporter
from .scope import ScopeError, validate_targets


async def camposter(
    targets: Iterable[str],
    *,
    data: str | None = None,
    data_file: Path | None = None,
    content_type: str = "application/x-www-form-urlencoded",
    concurrency: int = 20,
    timeout: float = 10.0,
    allow_public: bool = False,
    reporter: Reporter | None = None,
) -> list[dict]:
    """POST *data* (or contents of *data_file*) to each *target*.

    Only send data to endpoints you own or are authorized to test.
    """
    from urllib.parse import urlparse

    host_list = validate_targets(targets, allow_public=allow_public)
    payload: str | bytes = ""
    if data_file is not None:
        payload = data_file.read_text(errors="replace")
    elif data is not None:
        payload = data
    else:
        raise ValueError("Either --data or --data-file is required.")

    urls: list[str] = []
    for h in host_list:
        if urlparse(h).scheme:
            urls.append(h)
        else:
            urls.append(f"http://{h}")

    semaphore = asyncio.Semaphore(concurrency)
    results: list[dict] = []

    async with httpx.AsyncClient(
        headers={"User-Agent": "h4ck-modern/0.1", "Content-Type": content_type},
        verify=True,
        timeout=timeout,
    ) as client:

        async def post(url):
            async with semaphore:
                try:
                    r = await client.post(url, content=payload)
                    return {
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "content_type": r.headers.get("content-type"),
                    }
                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    return {"url": url, "error": str(exc)}

        responses = await asyncio.gather(*[post(u) for u in urls])

    for res in responses:
        results.append(res)
        if reporter is not None and "error" not in res:
            reporter.add(
                Finding(
                    category="camposter",
                    target=res["url"],
                    detail=f"POST {res['status']} size={res['size']}",
                    status=res["status"],
                )
            )

    results.sort(key=lambda r: r.get("url", ""))
    return results
