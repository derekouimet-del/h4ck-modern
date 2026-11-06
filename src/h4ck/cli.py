"""Command-line interface for h4ck-modern — all original features, modernized.

Dangerous features (random internet scanning, RTSP brute-forcing) require
explicit opt-in flags and only run against targets you own or have written
authorization to test.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

from .encoding import dec_ip, dec_text, enc_ip, enc_text
from .fortune import fortune_scan as fortune_scan_module, fortune_http_cam as fortune_http_cam_module, fortune_rtsp as fortune_rtsp_module
from .gip import get_public_ip
from .http_scan import http_scan as http_scan_module
from .netbat import scan_ports
from .output import Finding, Reporter
from .results import ResultsDB
from .rtsp import rtsp_brute as rtsp_brute_module, rtsp_capture as rtsp_capture_module
from .scope import ScopeError, validate_targets, confirm_random_internet
from .vpn import vpn_connect
from .webmap import scan_web
from .whois import whois_lookup
from .camposter import camposter as camposter_module
from .camdike import camdike_module, camdike_lite_module, camdike_lite_no_brute_module

app = typer.Typer(
    name="h4ck",
    help="Modern async network & web reconnaissance for authorized targets only.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


def _reporter(json_out: bool) -> Reporter:
    return Reporter(json_out=json_out)


@app.command()
def scan(
    targets: List[str] = typer.Argument(..., help="Host/IP/CIDR to scan"),
    ports: str = typer.Option("22,80,443,8080", "--ports", "-p", help="Port spec, e.g. 22,80,443,8000-9000"),
    concurrency: int = typer.Option(200, "--concurrency", "-c", help="Max concurrent connections"),
    timeout: float = typer.Option(2.0, "--timeout", "-t", help="Per-connection timeout (seconds)"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow scanning public targets"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of rich text"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save results to SQLite DB"),
) -> None:
    """TCP port scan (netbat / port_scanner)."""
    reporter = _reporter(json_out)

    async def _run():
        await scan_ports(
            targets,
            ports,
            concurrency=concurrency,
            timeout=timeout,
            allow_public=allow_public,
            reporter=reporter,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()
    if save:
        db = ResultsDB(save)
        for f in reporter.findings:
            db.add(f["category"], f["target"], f["detail"], f["port"], f["status"], f["extra"])
        db.close()
        console.print(f"[green]Saved[/green] results to {save}")


@app.command()
def webmap(
    targets: List[str] = typer.Argument(..., help="URL or host to scan"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Max concurrent requests"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Per-request timeout (seconds)"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow scanning public targets"),
    no_fuzz: bool = typer.Option(False, "--no-fuzz", help="Skip common-path probing"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of rich text"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save results to SQLite DB"),
) -> None:
    """Web tech / CMS detection + directory probe (webmap)."""
    reporter = _reporter(json_out)

    async def _run():
        await scan_web(
            targets,
            concurrency=concurrency,
            timeout=timeout,
            allow_public=allow_public,
            fuzz=not no_fuzz,
            reporter=reporter,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()
    if save:
        db = ResultsDB(save)
        for f in reporter.findings:
            db.add(f["category"], f["target"], f["detail"], f["port"], f["status"], f["extra"])
        db.close()
        console.print(f"[green]Saved[/green] results to {save}")


@app.command()
def http_scan(
    targets: List[str] = typer.Argument(..., help="URL or host to scan"),
    concurrency: int = typer.Option(50, "--concurrency", "-c", help="Max concurrent requests"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Per-request timeout"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow scanning public targets"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """HTTP status/header scanner (http_scan)."""
    reporter = _reporter(json_out)

    async def _run():
        await http_scan_module(
            targets,
            concurrency=concurrency,
            timeout=timeout,
            allow_public=allow_public,
            reporter=reporter,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()


@app.command()
def fortune(
    count: int = typer.Option(100, "--count", "-n", help="Number of random IPs to generate/scan"),
    ports: str = typer.Option("80,443,554,8080", "--ports", "-p", help="Port spec"),
    random_internet: bool = typer.Option(False, "--random-internet", help="Enable random public IP scanning"),
    confirm: bool = typer.Option(False, "--confirm", help="Skip interactive confirmation"),
    seed: Optional[int] = typer.Option(None, "--seed", help="RNG seed"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save results to SQLite DB"),
) -> None:
    """Random-IP scanner / generator (fortune*, fortune_port)."""
    if random_internet and not confirm:
        if not confirm_random_internet():
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(code=0)

    reporter = _reporter(json_out)

    async def _run():
        return await fortune_scan_module(
            count,
            ports=ports,
            allow_random=random_internet,
            reporter=reporter,
            seed=seed,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()
    if save:
        db = ResultsDB(save)
        for f in reporter.findings:
            db.add(f["category"], f["target"], f["detail"], f["port"], f["status"], f["extra"])
        db.close()
        console.print(f"[green]Saved[/green] results to {save}")


@app.command()
def fortune_http_cam(
    count: int = typer.Option(50, "--count", "-n", help="Number of random IPs to probe"),
    random_internet: bool = typer.Option(False, "--random-internet", help="Enable random public IP scanning"),
    confirm: bool = typer.Option(False, "--confirm", help="Skip interactive confirmation"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Probe random IPs for HTTP camera/web interfaces (fortune_http_cam)."""
    if random_internet and not confirm:
        if not confirm_random_internet():
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(code=0)

    reporter = _reporter(json_out)

    async def _run():
        return await fortune_http_cam_module(
            count, allow_random=random_internet, reporter=reporter
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()


@app.command()
def fortune_rtsp(
    count: int = typer.Option(50, "--count", "-n", help="Number of random IPs to probe"),
    random_internet: bool = typer.Option(False, "--random-internet", help="Enable random public IP scanning"),
    confirm: bool = typer.Option(False, "--confirm", help="Skip interactive confirmation"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Probe random IPs for open RTSP port 554 (fortune_rtsp)."""
    if random_internet and not confirm:
        if not confirm_random_internet():
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(code=0)

    reporter = _reporter(json_out)

    async def _run():
        return await fortune_rtsp_module(
            count, allow_random=random_internet, reporter=reporter
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()


@app.command()
def rtsp_brute(
    targets: List[str] = typer.Argument(..., help="Host/IP to brute-force RTSP on"),
    port: int = typer.Option(554, "--port", help="RTSP port"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", "-w", help="Wordlist file (user:pass or user per line)"),
    authorize_brute: bool = typer.Option(False, "--authorize-brute", help="Authorize RTSP brute-forcing"),
    concurrency: int = typer.Option(50, "--concurrency", "-c", help="Max concurrent attempts"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save results to SQLite DB"),
) -> None:
    """RTSP credential brute-force (rtsp_brute).

    Requires --authorize-brute and --wordlist. Only against hosts you own or
    have written authorization to test. No password dictionary is bundled.
    """
    reporter = _reporter(json_out)

    async def _run():
        return await rtsp_brute_module(
            targets,
            port=port,
            wordlist=wordlist,
            authorize_brute=authorize_brute,
            concurrency=concurrency,
            reporter=reporter,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()
    if save:
        db = ResultsDB(save)
        for f in reporter.findings:
            db.add(f["category"], f["target"], f["detail"], f["port"], f["status"], f["extra"])
        db.close()
        console.print(f"[green]Saved[/green] results to {save}")


@app.command()
def rtsp_capture(
    targets: List[str] = typer.Argument(..., help="Host/IP to check RTSP reachability"),
    port: int = typer.Option(554, "--port", help="RTSP port"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save results to SQLite DB"),
) -> None:
    """RTSP stream reachability probe (rtsp_capture)."""
    reporter = _reporter(json_out)

    async def _run():
        return await rtsp_capture_module(targets, port=port, reporter=reporter)

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()
    if save:
        db = ResultsDB(save)
        for f in reporter.findings:
            db.add(f["category"], f["target"], f["detail"], f["port"], f["status"], f["extra"])
        db.close()
        console.print(f"[green]Saved[/green] results to {save}")


@app.command()
def camposter(
    targets: List[str] = typer.Argument(..., help="URL or host to POST to"),
    data: Optional[str] = typer.Option(None, "--data", "-d", help="Raw POST body"),
    data_file: Optional[Path] = typer.Option(None, "--data-file", "-D", help="File to read POST body from"),
    content_type: str = typer.Option("application/x-www-form-urlencoded", "--content-type", "-H", help="Content-Type header"),
    concurrency: int = typer.Option(20, "--concurrency", "-c", help="Max concurrent POSTs"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Per-request timeout"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow public targets"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save results to SQLite DB"),
) -> None:
    """POST data to targets (camposter). Only POST to endpoints you own/authorize."""
    reporter = _reporter(json_out)

    async def _run():
        return await camposter_module(
            targets,
            data=data,
            data_file=data_file,
            content_type=content_type,
            concurrency=concurrency,
            timeout=timeout,
            allow_public=allow_public,
            reporter=reporter,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)
    reporter.summary()
    if save:
        db = ResultsDB(save)
        for f in reporter.findings:
            db.add(f["category"], f["target"], f["detail"], f["port"], f["status"], f["extra"])
        db.close()
        console.print(f"[green]Saved[/green] results to {save}")


@app.command()
def whois(
    target: str = typer.Argument(..., help="Domain or IP to look up"),
    port: int = typer.Option(43, "--port", help="WHOIS port"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Timeout (seconds)"),
) -> None:
    """WHOIS lookup (whois)."""
    try:
        text = whois_lookup(target, port=port, timeout=timeout)
    except Exception as exc:
        console.print(f"[red]WHOIS error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(text)


@app.command()
def vpn(
    config: Path = typer.Argument(..., help="OpenVPN config file (.ovpn)"),
    daemon: bool = typer.Option(False, "--daemon", help="Run in background"),
) -> None:
    """Connect to an OpenVPN server (vpn)."""
    try:
        code = vpn_connect(config, daemon=daemon)
        raise typer.Exit(code=code)
    except (FileNotFoundError, RuntimeError) as exc:
        console.print(f"[red]VPN error:[/red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def enc_ip_cmd(
    ip: str = typer.Argument(..., help="IP address to encode"),
    fmt: str = typer.Option("int", "--format", "-f", help="Format: int, hex, binary, octal, ipv6-mapped"),
) -> None:
    """Encode an IP address (enc_ip)."""
    try:
        console.print(enc_ip(ip, fmt))
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def dec_ip_cmd(
    value: str = typer.Argument(..., help="Encoded value"),
    fmt: str = typer.Option("int", "--format", "-f", help="Format: int, hex, binary, octal"),
) -> None:
    """Decode an IP address (dec_ip)."""
    try:
        console.print(dec_ip(value, fmt))
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def enc_text_cmd(
    text: str = typer.Argument(..., help="Text to encode"),
    fmt: str = typer.Option("base64", "--format", "-f", help="Format: base64, hex, binary, rot13, url"),
) -> None:
    """Encode text (enc_text)."""
    console.print(enc_text(text, fmt))


@app.command()
def dec_text_cmd(
    text: str = typer.Argument(..., help="Encoded text"),
    fmt: str = typer.Option("base64", "--format", "-f", help="Format: base64, hex, binary, rot13, url"),
) -> None:
    """Decode text (dec_text)."""
    console.print(dec_text(text, fmt))


@app.command()
def gip() -> None:
    """Get public IP address (gip)."""
    try:
        console.print(get_public_ip())
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show version."""
    from . import __version__

    console.print(f"h4ck-modern {__version__}")


@app.command()
def camdike(
    count: int = typer.Option(32, "--count", "-c", help="Random IPs to scan"),
    random_internet: bool = typer.Option(
        False, "--random-internet", help="Enable random public IP scanning"
    ),
    confirm: bool = typer.Option(
        False, "--confirm", help="Skip interactive confirmation"
    ),
    authorize_brute: bool = typer.Option(
        False, "--authorize-brute", help="Authorize RTSP brute-forcing"
    ),
    wordlist: Optional[Path] = typer.Option(
        None, "--wordlist", "-w", help="Wordlist file"
    ),
    post_target: str = typer.Option(
        "http://localhost", "--post-target", help="camposter target URL"
    ),
    post_data: Optional[str] = typer.Option(
        None, "--post-data", "-d", help="POST body"
    ),
    loop: bool = typer.Option(
        True, "--loop/--no-loop", help="Run in a loop"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
    timeout_minutes: Optional[float] = typer.Option(
        None, "--timeout-minutes", help="Stop after N minutes"
    ),
) -> None:
    """Full camdike pipeline: scan -> brute -> capture -> post (camdike.sh)."""
    async def _run():
        await camdike_module(
            count=count,
            random_internet=random_internet,
            confirm=confirm,
            authorize_brute=authorize_brute,
            wordlist=wordlist,
            post_target=post_target,
            post_data=post_data,
            loop=loop,
            json_out=json_out,
            timeout_minutes=timeout_minutes,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def camdike_lite(
    count: int = typer.Option(32, "--count", "-c", help="Random IPs to scan"),
    random_internet: bool = typer.Option(
        False, "--random-internet", help="Enable random public IP scanning"
    ),
    confirm: bool = typer.Option(
        False, "--confirm", help="Skip interactive confirmation"
    ),
    authorize_brute: bool = typer.Option(
        False, "--authorize-brute", help="Authorize RTSP brute-forcing"
    ),
    wordlist: Optional[Path] = typer.Option(
        None, "--wordlist", "-w", help="Wordlist file"
    ),
    post_target: str = typer.Option(
        "http://localhost", "--post-target", help="camposter target URL"
    ),
    post_data: Optional[str] = typer.Option(
        None, "--post-data", "-d", help="POST body"
    ),
    loop: bool = typer.Option(
        True, "--loop/--no-loop", help="Run in a loop"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Lite camdike pipeline (camdike_lite.sh)."""
    async def _run():
        await camdike_lite_module(
            count=count,
            random_internet=random_internet,
            confirm=confirm,
            authorize_brute=authorize_brute,
            wordlist=wordlist,
            post_target=post_target,
            post_data=post_data,
            loop=loop,
            json_out=json_out,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def camdike_lite_no_brute(
    count: int = typer.Option(32, "--count", "-c", help="Random IPs to scan"),
    random_internet: bool = typer.Option(
        False, "--random-internet", help="Enable random public IP scanning"
    ),
    confirm: bool = typer.Option(
        False, "--confirm", help="Skip interactive confirmation"
    ),
    post_target: str = typer.Option(
        "http://localhost", "--post-target", help="camposter target URL"
    ),
    post_data: Optional[str] = typer.Option(
        None, "--post-data", "-d", help="POST body"
    ),
    loop: bool = typer.Option(
        True, "--loop/--no-loop", help="Run in a loop"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Lite camdike without brute force (camdike_lite_no_brute.sh)."""
    async def _run():
        await camdike_lite_no_brute_module(
            count=count,
            random_internet=random_internet,
            confirm=confirm,
            post_target=post_target,
            post_data=post_data,
            loop=loop,
            json_out=json_out,
        )

    try:
        asyncio.run(_run())
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
