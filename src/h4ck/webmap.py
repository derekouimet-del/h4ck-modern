"""Async web tech / CMS detector + directory fuzzer — modern webmap."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urljoin, urlparse

import httpx

from .output import Finding, Reporter
from .scope import ScopeError, validate_targets
from .utils import expand_hosts


CMS_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "Drupal": [r"drupal.settings", r"/sites/default/", r"Drupal"],
    "Joomla": [r"/media/system/", r"Joomla!"],
    "Shopify": [r"Shopify", r"cdn.shopify.com"],
    "Magento": [r"/skin/frontend/", r"Mage\.cookies"],
    "Ghost": [r"ghost\/", r"/ghost/"],
}

TECH_SIGNATURES = {
    "React": [r"react(?:-dom)?\.production\.min\.js", r"__REACT_DEVTOOLS__"],
    "Vue.js": [r"vue\.production\.min\.js", r"__VUE__"],
    "Angular": [r"ng-version", r"angular\.js"],
    "jQuery": [r"jquery[^>]*\.js"],
    "Bootstrap": [r"bootstrap[^>]*\.css", r"bootstrap[^>]*\.js"],
    "Google Analytics": [r"google-analytics\.com", r"gtag\("],
    "Google Tag Manager": [r"googletagmanager\.com"],
    "Cloudflare": [r"cloudflare", r"__cf_"],
    "Nginx": [r"nginx"],
    "Apache": [r"apache"],
}

FUZZ_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/",
    "/.env",
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/phpmyadmin/",
    "/server-status",
    "/.well-known/security.txt",
]


def _extract_title(text: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else None


def _match_signatures(text: str, signatures: dict[str, list[str]]) -> list[str]:
    found = []
    for name, patterns in signatures.items():
        if any(re.search(p, text, re.IGNORECASE) for p in patterns):
            found.append(name)
    return found


async def _fetch(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    follow_redirects: bool = True,
) -> httpx.Response | None:
    async with semaphore:
        try:
            return await client.get(
                url, timeout=10.0, follow_redirects=follow_redirects
            )
        except (httpx.RequestError, httpx.HTTPStatusError):
            return None


async def scan_web(
    targets: Iterable[str],
    *,
    concurrency: int = 10,
    timeout: float = 10.0,
    allow_public: bool = False,
    fuzz: bool = True,
    reporter: Reporter | None = None,
    verbose: bool = False,
) -> list[dict]:
    plain_hosts: list[str] = []
    url_targets: list[str] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if urlparse(t).scheme:
            url_targets.append(t)
            plain_hosts.append(urlparse(t).hostname or t)
        else:
            plain_hosts.append(t)

    validated_hosts = validate_targets(plain_hosts, allow_public=allow_public)

    urls: list[str] = list(url_targets)
    for h in validated_hosts:
        if urlparse(h).scheme:
            urls.append(h)
        else:
            urls.append(f"http://{h}")
            urls.append(f"https://{h}")

    seen: set[str] = set()
    urls = [u for u in urls if not (u in seen or seen.add(u))]

    semaphore = asyncio.Semaphore(concurrency)
    results: list[dict] = []

    async with httpx.AsyncClient(
        headers={"User-Agent": "h4ck-modern/0.1 (authorized reconnaissance)"},
        verify=True,
    ) as client:
        responses = await asyncio.gather(
            *[_fetch(client, u, semaphore) for u in urls], return_exceptions=True
        )

    for url, resp in zip(urls, responses):
        if not isinstance(resp, httpx.Response):
            if verbose and reporter is not None:
                reporter.add(
                    Finding(
                        category="web",
                        target=url,
                        detail="connection failed",
                    )
                )
            continue

        text = resp.text
        server = resp.headers.get("server")
        title = _extract_title(text)
        cms = _match_signatures(text, CMS_SIGNATURES)
        techs = _match_signatures(text, TECH_SIGNATURES)
        if server and "nginx" in server.lower() and "Nginx" not in techs:
            techs.append("Nginx")
        if server and "apache" in server.lower() and "Apache" not in techs:
            techs.append("Apache")

        found_paths: list[str] = []
        if fuzz:
            path_sem = asyncio.Semaphore(max(1, concurrency // 2))
            path_tasks = [
                _fetch(client, urljoin(url, p), path_sem, follow_redirects=False)
                for p in FUZZ_PATHS
            ]
            path_resps = await asyncio.gather(*path_tasks, return_exceptions=True)
            for path, presp in zip(FUZZ_PATHS, path_resps):
                if isinstance(presp, httpx.Response) and presp.status_code in (
                    200,
                    301,
                    302,
                    403,
                ):
                    found_paths.append(f"{path} ({presp.status_code})")

        result = {
            "url": url,
            "status": resp.status_code,
            "title": title,
            "server": server,
            "cms": cms,
            "techs": techs,
            "found_paths": found_paths,
            "headers": dict(resp.headers),
        }
        results.append(result)

        if reporter is not None:
            detail = f"status={resp.status_code}"
            if title:
                detail += f" title={title!r}"
            if cms:
                detail += f" cms={','.join(cms)}"
            if techs:
                detail += f" techs={','.join(techs)}"
            if found_paths:
                detail += f" paths={','.join(found_paths)}"
            if not verbose and not cms and not techs and not found_paths:
                continue
            reporter.add(
                Finding(
                    category="web",
                    target=url,
                    detail=detail,
                    status=resp.status_code,
                    extra={"server": server, "cms": cms, "techs": techs},
                )
            )

    results.sort(key=lambda r: r["url"])
    return results
