# h4ck-modern

Modern, async rewrite of [fagci/h4ck](https://github.com/fagci/h4ck) — network &
web reconnaissance tooling for **targets you own or have written authorization
to test**.

Every original feature from the legacy repo is included, rebuilt with Python
3.10+, `asyncio`, `httpx`, `typer`, and `rich`. Dangerous features (random
internet scanning, credential brute-forcing) are opt-in only and require
explicit confirmation.

---

## Table of contents

1. [Install](#install)
2. [Quick start](#quick-start)
3. [Command reference](#command-reference)
   - [`scan`](#scan) — TCP port scan
   - [`webmap`](#webmap) — CMS / tech detection + directory probing
   - [`http-scan`](#http-scan) — HTTP status / header scan
   - [`fortune`](#fortune) — random-IP port scanner
   - [`fortune-http-cam`](#fortune-http-cam) — random-IP HTTP camera probe
   - [`fortune-rtsp`](#fortune-rtsp) — random-IP RTSP probe
   - [`rtsp-brute`](#rtsp-brute) — RTSP credential brute-force
   - [`rtsp-capture`](#rtsp-capture) — RTSP stream reachability probe
   - [`camdike`](#camdike) — full pipeline (scan → brute → capture → post)
   - [`camdike-lite`](#camdike-lite) — lighter pipeline
   - [`camdike-lite-no-brute`](#camdike-lite-no-brute) — pipeline without brute-force
   - [`camposter`](#camposter) — POST data to targets
   - [`whois`](#whois) — raw WHOIS lookup
   - [`vpn`](#vpn) — OpenVPN connector
   - [`enc-ip-cmd` / `dec-ip-cmd`](#ip-encoding) — IP address encoding
   - [`enc-text-cmd` / `dec-text-cmd`](#text-encoding) — text encoding
   - [`gip`](#gip) — public IP lookup
   - [`version`](#version)
4. [Output formats](#output-formats)
5. [Ethics & scope controls](#ethics--scope-controls)
6. [License](#license)

---

## Install

```bash
git clone https://github.com/<your-username>/h4ck-modern.git
cd h4ck-modern
pip install -e .
```

This installs the `h4ck` entry point on your `PATH`.

Requirements: Python 3.10+, `httpx`, `typer[all]`, `rich`.

---

## Quick start

Scan your own LAN for open ports:

```bash
h4ck scan 192.168.1.0/24 --ports 22,80,443,8080 --concurrency 200
```

Scan a web application you own:

```bash
h4ck webmap https://my-app.example.com --concurrency 10
```

Get your public IP:

```bash
h4ck gip
```

Encode an IP address:

```bash
h4ck enc-ip-cmd 192.168.1.1 --format hex
# 0xc0a80101
```

---

## Command reference

### `scan` — TCP port scan (netbat / port_scanner)

Asynchronously scans hosts, CIDR networks, or a file of hosts for open TCP
ports, reporting per-port latency.

```bash
# Scan a single host
h4ck scan 192.168.1.5 --ports 22,80,443,8080

# Scan a CIDR range
h4ck scan 10.0.0.0/24 --ports 1-1024 --concurrency 300

# Scan hosts from a file (one per line, CIDR supported)
h4ck scan hosts.txt --ports 80,443

# Public target you own (opt-in required)
h4ck scan 203.0.113.10 --ports 22,80 --allow-public

# JSON output
h4ck scan 192.168.1.5 --ports 22,80,443 --json

# Save results to SQLite
h4ck scan 192.168.1.5 --ports 22,80,443 --save local/results.db
```

**Options**

| Option | Default | Description |
|---|---|---|
| `targets` | (required) | Host/IP/CIDR or path to a host list file |
| `--ports` / `-p` | `22,80,443,8080` | Port spec, e.g. `22,80,443,8000-9000` |
| `--concurrency` / `-c` | `200` | Max concurrent connections |
| `--timeout` / `-t` | `2.0` | Per-connection timeout (seconds) |
| `--allow-public` | — | Allow scanning public (non-RFC1918) targets |
| `--json` | — | Emit JSON instead of rich text |
| `--save` | — | Save findings to a SQLite database file |

---

### `webmap` — Web tech / CMS detection + directory probe (webmap)

Detects CMS platforms, frontend technologies, server headers, page titles, and
probes common paths (`/robots.txt`, `/admin/`, `/.git/`, etc.) on web targets.

```bash
# Scan a web app you own
h4ck webmap https://my-app.example.com

# Skip common-path fuzzing (faster, quieter)
h4ck webmap https://my-app.example.com --no-fuzz

# Public target you own
h4ck webmap https://my-server.example.com --allow-public

# JSON output
h4ck webmap https://my-app.example.com --json

# Save to SQLite
h4ck webmap https://my-app.example.com --save local/webmap.db
```

**Options**

| Option | Default | Description |
|---|---|---|
| `targets` | (required) | URL or host to scan |
| `--concurrency` / `-c` | `10` | Max concurrent requests |
| `--timeout` / `-t` | `10.0` | Per-request timeout (seconds) |
| `--allow-public` | — | Allow public targets |
| `--no-fuzz` | — | Skip common-path probing |
| `--json` | — | Emit JSON |
| `--save` | — | Save findings to SQLite |

---

### `http-scan` — HTTP status / header scanner (http_scan)

Performs HTTP GET against targets and reports status code, body size, server
header, content type, and final URL after redirects.

```bash
h4ck http-scan https://my-app.example.com --allow-public
h4ck http-scan 192.168.1.5 --concurrency 100 --json
h4ck http-scan targets.txt --allow-public --concurrency 50
```

**Options**

| Option | Default | Description |
|---|---|---|
| `targets` | (required) | URL or host to scan |
| `--concurrency` / `-c` | `50` | Max concurrent requests |
| `--timeout` / `-t` | `10.0` | Per-request timeout (seconds) |
| `--allow-public` | — | Allow public targets |
| `--json` | — | Emit JSON |

---

### `fortune` — Random-IP scanner / generator (fortune*, fortune_port)

Generates random public IPv4 addresses and scans them for open ports. This is
**random internet scanning** — only use against systems you own or have written
authorization to test.

```bash
# Generate and scan 100 random IPs (requires confirmation)
h4ck fortune --count 100 --ports 80,443,554,8080 --random-internet --confirm

# With a fixed RNG seed for reproducible results
h4ck fortune --count 50 --ports 554 --random-internet --confirm --seed 42

# JSON output
h4ck fortune --count 25 --random-internet --confirm --json

# Save to SQLite
h4ck fortune --count 50 --random-internet --confirm --save local/fortune.db
```

**Options**

| Option | Default | Description |
|---|---|---|
| `--count` / `-n` | `100` | Number of random IPs to generate/scan |
| `--ports` / `-p` | `80,443,554,8080` | Port spec |
| `--random-internet` | — | Enable random public IP scanning |
| `--confirm` | — | Skip interactive confirmation |
| `--seed` | — | RNG seed for reproducibility |
| `--json` | — | Emit JSON |
| `--save` | — | Save findings to SQLite |

---

### `fortune-http-cam` — Random-IP HTTP camera probe (fortune_http_cam)

Probes random public IPs for exposed HTTP camera/web interfaces on ports 80
and 8080.

```bash
h4ck fortune-http-cam --count 50 --random-internet --confirm
h4ck fortune-http-cam --count 100 --random-internet --confirm --json
```

**Options**

| Option | Default | Description |
|---|---|---|
| `--count` / `-n` | `50` | Number of random IPs to probe |
| `--random-internet` | — | Enable random public IP scanning |
| `--confirm` | — | Skip interactive confirmation |
| `--json` | — | Emit JSON |

---

### `fortune-rtsp` — Random-IP RTSP probe (fortune_rtsp)

Probes random public IPs for open RTSP port 554.

```bash
h4ck fortune-rtsp --count 50 --random-internet --confirm
h4ck fortune-rtsp --count 100 --random-internet --confirm --json
```

**Options**

| Option | Default | Description |
|---|---|---|
| `--count` / `-n` | `50` | Number of random IPs to probe |
| `--random-internet` | — | Enable random public IP scanning |
| `--confirm` | — | Skip interactive confirmation |
| `--json` | — | Emit JSON |

---

### `rtsp-brute` — RTSP credential brute-force (rtsp_brute)

Attempts RTSP authentication against targets using a user-supplied wordlist.
**No password dictionary is bundled** — you supply your own wordlist (one
`user:pass` or `user` per line).

```bash
# Requires explicit authorization opt-in
h4ck rtsp-brute 10.0.0.5 --port 554 --wordlist my_wordlist.txt --authorize-brute

# Multiple targets from a file
h4ck rtsp-brute targets.txt --port 554 --wordlist wl.txt --authorize-brute --json

# Save hits to SQLite
h4ck rtsp-brute 10.0.0.5 --port 554 --wordlist wl.txt --authorize-brute --save local/rtsp_brute.db
```

**Options**

| Option | Default | Description |
|---|---|---|
| `targets` | (required) | Host/IP or path to host list |
| `--port` | `554` | RTSP port |
| `--wordlist` / `-w` | (required) | Wordlist file (`user:pass` or `user` per line) |
| `--authorize-brute` | — | Authorize RTSP brute-forcing |
| `--concurrency` / `-c` | `50` | Max concurrent attempts |
| `--json` | — | Emit JSON |
| `--save` | — | Save findings to SQLite |

> ⚠️ Credential brute-forcing against third-party devices is illegal in most
> jurisdictions. Only run against systems you own or have written authorization
> to test.

---

### `rtsp-capture` — RTSP stream reachability probe (rtsp_capture)

Checks whether RTSP streams are reachable on target hosts (sends RTSP OPTIONS,
reports whether a valid RTSP response comes back). Does not download or store
media.

```bash
h4ck rtsp-capture 10.0.0.5 --port 554 --allow-public
h4ck rtsp-capture targets.txt --port 554 --json --save local/rtsp_capture.db
```

**Options**

| Option | Default | Description |
|---|---|---|
| `targets` | (required) | Host/IP or path to host list |
| `--port` | `554` | RTSP port |
| `--allow-public` | — | Allow public targets |
| `--json` | — | Emit JSON |
| `--save` | — | Save findings to SQLite |

---

### `camdike` — Full pipeline (camdike.sh)

The complete camdike orchestration: random RTSP scan → RTSP brute-force → RTSP
capture → POST results. Runs in a loop until interrupted (Ctrl+C).

```bash
# Full pipeline, loops until interrupted
h4ck camdike --count 32 --random-internet --confirm \
    --authorize-brute --wordlist wl.txt \
    --post-target https://my-collector.example.com/ingest \
    --post-data "source=camdike"

# Run once instead of looping
h4ck camdike --count 32 --random-internet --confirm \
    --authorize-brute --wordlist wl.txt --no-loop

# Stop after N minutes
h4ck camdike --count 32 --random-internet --confirm \
    --authorize-brute --wordlist wl.txt --timeout-minutes 60

# JSON output
h4ck camdike --count 32 --random-internet --confirm \
    --authorize-brute --wordlist wl.txt --json
```

**Options**

| Option | Default | Description |
|---|---|---|
| `--count` / `-c` | `32` | Random IPs to scan per cycle |
| `--random-internet` | — | Enable random public IP scanning |
| `--confirm` | — | Skip interactive confirmation |
| `--authorize-brute` | — | Authorize RTSP brute-forcing |
| `--wordlist` / `-w` | — | Wordlist file (required if brute-forcing) |
| `--post-target` | `http://localhost` | camposter target URL |
| `--post-data` / `-d` | — | POST body |
| `--loop` / `--no-loop` | `--loop` | Run continuously or once |
| `--timeout-minutes` | — | Stop after N minutes |
| `--json` | — | Emit JSON |

---

### `camdike-lite` — Lighter pipeline (camdike_lite.sh)

Same as `camdike` but a lighter-weight configuration.

```bash
h4ck camdike-lite --count 32 --random-internet --confirm \
    --authorize-brute --wordlist wl.txt --no-loop
```

**Options**: Same as `camdike` (minus `--timeout-minutes`).

---

### `camdike-lite-no-brute` — Pipeline without brute-force (camdike_lite_no_brute.sh)

Random RTSP scan → RTSP capture → POST. Skips the brute-force step entirely,
but still performs random internet scanning (requires `--random-internet` +
`--confirm`).

```bash
h4ck camdike-lite-no-brute --count 32 --random-internet --confirm \
    --post-target https://my-collector.example.com/ingest --no-loop
```

**Options**: Same as `camdike-lite` (no `--authorize-brute`, no `--wordlist`).

---

### `camposter` — POST data to targets (camposter)

Sends an HTTP POST body to one or more targets. Only POST to endpoints you own
or are authorized to test.

```bash
# POST raw data
h4ck camposter https://my-app.example.com/hook --data "foo=bar"

# POST contents of a file
h4ck camposter https://my-app.example.com/hook --data-file payload.txt

# Custom content type
h4ck camposter https://my-app.example.com/api \
    --data '{"key":"value"}' --content-type "application/json"

# JSON output
h4ck camposter https://my-app.example.com/hook --data "test" --json --save local/camposter.db
```

**Options**

| Option | Default | Description |
|---|---|---|
| `targets` | (required) | URL or host to POST to |
| `--data` / `-d` | — | Raw POST body |
| `--data-file` / `-D` | — | File to read POST body from |
| `--content-type` / `-H` | `application/x-www-form-urlencoded` | Content-Type header |
| `--concurrency` / `-c` | `20` | Max concurrent POSTs |
| `--timeout` / `-t` | `10.0` | Per-request timeout (seconds) |
| `--allow-public` | — | Allow public targets |
| `--json` | — | Emit JSON |
| `--save` | — | Save findings to SQLite |

---

### `whois` — Raw WHOIS lookup (whois)

Performs a raw WHOIS query against IANA and follows referrals to the
appropriate RIR (ARIN, RIPE, APNIC, etc.).

```bash
h4ck whois example.com
h4ck whois 8.8.8.8
h4ck whois example.com --port 43 --timeout 15
```

**Options**

| Option | Default | Description |
|---|---|---|
| `target` | (required) | Domain or IP to look up |
| `--port` | `43` | WHOIS port |
| `--timeout` / `-t` | `10.0` | Timeout (seconds) |

---

### `vpn` — OpenVPN connector (vpn)

Connects to an OpenVPN server using a `.ovpn` config file. Requires the
`openvpn` binary installed on your system.

```bash
# Foreground connection
h4ck vpn my-server.ovpn

# Background (daemonized)
h4ck vpn my-server.ovpn --daemon
```

**Options**

| Option | Default | Description |
|---|---|---|
| `config` | (required) | OpenVPN config file (.ovpn) |
| `--daemon` | — | Run in background |

---

### IP encoding (`enc_ip` / `dec_ip`)

```bash
h4ck enc-ip-cmd 192.168.1.1 --format int      # 3232235777
h4ck enc-ip-cmd 192.168.1.1 --format hex      # 0xc0a80101
h4ck enc-ip-cmd 192.168.1.1 --format binary   # 0b110000001010100000000001
h4ck enc-ip-cmd 192.168.1.1 --format octal    # 0o30012000001
h4ck enc-ip-cmd 10.0.0.1 --format ipv6-mapped # ::ffff:10.0.0.1

h4ck dec-ip-cmd 3232235777 --format int       # 192.168.1.1
h4ck dec-ip-cmd 0xc0a80101 --format hex       # 192.168.1.1
```

**Formats**: `int`, `hex`, `binary`, `octal`, `ipv6-mapped` (encode only).

---

### Text encoding (`enc_text` / `dec_text`)

```bash
h4ck enc-text-cmd "hello world" --format base64   # aGVsbG8gd29ybGQ=
h4ck enc-text-cmd "hello world" --format hex      # 68656c6c6f20776f726c64
h4ck enc-text-cmd "hello world" --format rot13    # uryyb jbeyq
h4ck enc-text-cmd "hello world" --format url      # hello%20world

h4ck dec-text-cmd aGVsbG8gd29ybGQ= --format base64  # hello world
h4ck dec-text-cmd "uryyb jbeyq" --format rot13      # hello world
```

**Formats**: `base64`, `hex`, `binary`, `rot13`, `url`.

---

### `gip` — Public IP address lookup

```bash
h4ck gip
# 198.44.139.150
```

---

### `version`

```bash
h4ck version
# h4ck-modern 0.1.0
```

---

## Output formats

### Rich console (default)

Findings are printed in color to the terminal:

```
open-port  127.0.0.1:443  open (1 ms)
web          https://example.com  status=200 title='Example Domain'
```

### JSON (`--json`)

Every command supports `--json` for machine-readable output:

```json
[
  {
    "category": "open-port",
    "target": "127.0.0.1",
    "detail": "open (1 ms)",
    "port": 443,
    "status": null,
    "extra": {}
  }
]
```

### SQLite (`--save <path>`)

Findings are appended to a SQLite database (`findings` table with columns:
`id`, `timestamp`, `category`, `target`, `detail`, `port`, `status`, `extra`).
Use `--save` on any command to persist results across runs.

```bash
h4ck scan 192.168.1.5 --ports 22,80,443 --save local/results.db
h4ck webmap https://my-app.example.com --save local/results.db
```

---

## Ethics & scope controls

h4ck-modern refuses to scan public (non-RFC1918) targets unless you explicitly
pass `--allow-public`. Higher-risk features require additional opt-in:

| Feature | Required flags |
|---|---|
| Public target scanning | `--allow-public` |
| Random internet scanning (`fortune*`) | `--random-internet` + `--confirm` |
| RTSP brute-force | `--authorize-brute` + `--wordlist` |

This tool does **not** support indiscriminate internet scanning against
third-party devices, accessing cameras/IoT devices you do not own, or any
activity that violates computer crime laws. **Only run it against systems you
own or have written permission to test.**

Unauthorized scanning may violate laws such as the U.S. Computer Fraud and
Abuse Act (CFAA), the U.K. Computer Misuse Act, and similar legislation in
other jurisdictions.

---

## Project structure

```
h4ck-modern/
├── pyproject.toml          # Package metadata & entry point
├── README.md               # This file
├── src/h4ck/
│   ├── __init__.py
│   ├── cli.py              # Typer CLI (all commands)
│   ├── scope.py            # Scope / authorization controls
│   ├── output.py           # Rich console + JSON reporter
│   ├── utils.py            # Port parsing, IP expansion, random IP gen
│   ├── netbat.py           # Async TCP port scanner
│   ├── webmap.py           # CMS/tech detector + path fuzzer
│   ├── http_scan.py        # HTTP status/header scanner
│   ├── fortune.py          # Random-IP scanners
│   ├── rtsp.py             # RTSP brute-force + capture
│   ├── camdike.py          # Orchestration pipelines
│   ├── camposter.py        # HTTP POST client
│   ├── whois.py            # Raw WHOIS lookup
│   ├── vpn.py              # OpenVPN connector
│   ├── encoding.py         # IP/text encoding utilities
│   ├── gip.py              # Public IP lookup
│   └── results.py          # SQLite results storage
└── local/                  # Runtime output dir (gitignored)
```

---

## License

MIT

---

⚠️ **Educational / authorized-use only.** The author is not responsible for
any misuse of this tool. Only scan systems you own or have written
authorization to test.