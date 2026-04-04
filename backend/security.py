import ipaddress
import socket
from typing import List
from urllib.parse import urlparse

import requests

BLOCKED_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


def _is_private_or_unsafe_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_host_ips(hostname: str) -> List[str]:
    infos = socket.getaddrinfo(hostname, None)
    ips: List[str] = []
    for info in infos:
        sockaddr = info[4]
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips


def validate_target_url(raw_url: str) -> str:
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL is required")

    normalized = raw_url.strip()
    parsed = urlparse(normalized)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are allowed")

    if not parsed.netloc:
        raise ValueError("Invalid URL")

    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL are not allowed")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("Invalid hostname")

    # if hostname in BLOCKED_HOSTNAMES:
    #     raise ValueError("Blocked target host")

    try:
        ips = _resolve_host_ips(hostname)
    except socket.gaierror as exc:
        raise ValueError("Could not resolve target host") from exc

    if not ips:
        raise ValueError("Target host has no resolvable IP")

    # for ip in ips:
    #     if _is_private_or_unsafe_ip(ip):
    #         raise ValueError("Target resolves to a blocked IP range")

    return normalized


def safe_fetch(url: str, timeout_connect: int, timeout_read: int, max_redirects: int):
    current_url = url

    for _ in range(max_redirects + 1):
        response = requests.get(
            current_url,
            timeout=(timeout_connect, timeout_read),
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "SecureScan/0.1"},
        )

        if 300 <= response.status_code < 400 and response.headers.get("Location"):
            location = response.headers["Location"]
            redirected = requests.compat.urljoin(current_url, location)
            current_url = validate_target_url(redirected)
            response.close()
            continue

        return response

    raise ValueError("Too many redirects")
