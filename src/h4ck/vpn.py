"""VPN module — modern replacement for vpn.py (OpenVPN connector)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .output import Finding, Reporter


def vpn_connect(
    config: str | Path,
    *,
    daemon: bool = False,
    reporter: Reporter | None = None,
) -> int:
    """Connect to an OpenVPN server using *config* (.ovpn).

    Requires the `openvpn` binary to be installed on the system. Runs in the
    foreground unless daemon=True (then it is backgrounded via nohup).
    """
    config = Path(config)
    if not config.exists():
        raise FileNotFoundError(f"OpenVPN config not found: {config}")

    openvpn = shutil.which("openvpn")
    if not openvpn:
        raise RuntimeError(
            "openvpn binary not found. Install openvpn (e.g. `brew install openvpn` "
            "or `apt-get install openvpn`)."
        )

    if reporter is not None:
        reporter.add(
            Finding(
                category="vpn",
                target=str(config),
                detail="connecting",
            )
        )

    if daemon:
        log = open(os.devnull, "w")
        subprocess.Popen(
            [openvpn, "--config", str(config)],
            stdout=log,
            stderr=log,
        )
        return 0
    return subprocess.call([openvpn, "--config", str(config)])
