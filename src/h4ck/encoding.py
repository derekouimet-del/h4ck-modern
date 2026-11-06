"""Encoding module — enc_ip / enc_text utilities."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import struct
from typing import Union


def enc_ip(ip: str, fmt: str = "int") -> str:
    """Encode an IP address.

    Formats: int, hex, binary, octal, ipv6-mapped.
    """
    ip_obj = ipaddress.ip_address(ip)
    if fmt == "int":
        return str(int(ip_obj))
    if fmt == "hex":
        return hex(int(ip_obj))
    if fmt == "binary":
        return bin(int(ip_obj))
    if fmt == "octal":
        return oct(int(ip_obj))
    if fmt == "ipv6-mapped" and ip_obj.version == 4:
        return str(ipaddress.IPv6Address(f"::ffff:{ip}"))
    raise ValueError(f"Unknown format: {fmt}")


def dec_ip(value: str, fmt: str = "int") -> str:
    """Decode an IP address from int/hex/binary/octal."""
    if fmt == "int":
        return str(ipaddress.ip_address(int(value)))
    if fmt == "hex":
        return str(ipaddress.ip_address(int(value, 16)))
    if fmt == "binary":
        return str(ipaddress.ip_address(int(value, 2)))
    if fmt == "octal":
        return str(ipaddress.ip_address(int(value, 8)))
    raise ValueError(f"Unknown format: {fmt}")


def enc_text(text: str, fmt: str = "base64") -> str:
    """Encode text. Formats: base64, hex, binary, rot13, url."""
    from urllib.parse import quote

    if fmt == "base64":
        return base64.b64encode(text.encode()).decode()
    if fmt == "hex":
        return text.encode().hex()
    if fmt == "binary":
        return " ".join(format(b, "08b") for b in text.encode())
    if fmt == "rot13":
        import codecs

        return codecs.encode(text, "rot_13")
    if fmt == "url":
        return quote(text, safe="")
    raise ValueError(f"Unknown format: {fmt}")


def dec_text(text: str, fmt: str = "base64") -> str:
    """Decode text."""
    from urllib.parse import unquote

    if fmt == "base64":
        return base64.b64decode(text).decode(errors="replace")
    if fmt == "hex":
        return bytes.fromhex(text).decode(errors="replace")
    if fmt == "binary":
        return "".join(chr(int(b, 2)) for b in text.split())
    if fmt == "rot13":
        import codecs

        return codecs.encode(text, "rot_13")
    if fmt == "url":
        return unquote(text)
    raise ValueError(f"Unknown format: {fmt}")


def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def int_to_ip(value: int) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        # Try IPv4 then IPv6
        if 0 <= value <= 2**32 - 1:
            return str(ipaddress.IPv4Address(value))
        return str(ipaddress.IPv6Address(value))
