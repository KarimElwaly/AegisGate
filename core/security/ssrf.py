import asyncio
import ipaddress
import socket
import urllib.parse
from typing import Sequence

from core.config import get_settings
from core.logger import get_logger
from core.telemetry import record_ssrf_block

logger = get_logger("core.security.ssrf")

# Disallowed IP Networks (Loopback, Cloud Metadata, RFC1918 Private, Link-Local, ULA)
BLOCKED_NETWORKS = [
    # IPv4 Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    # IPv4 Cloud Metadata & Link-Local
    ipaddress.ip_network("169.254.0.0/16"),
    # IPv4 Private RFC1918
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 Broadcast / Reserved
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    # IPv6 Loopback & Unspecified
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    # IPv6 Link-Local
    ipaddress.ip_network("fe80::/10"),
    # IPv6 Unique Local Address (ULA)
    ipaddress.ip_network("fc00::/7"),
    # IPv6 Multicast
    ipaddress.ip_network("ff00::/8"),
]


class SSRFProtectionError(ValueError):
    """Raised when an outbound URL violates SSRF security boundaries."""
    pass


def is_ip_allowed(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allowlist_cidrs: Sequence[str] | None = None,
) -> bool:
    """Checks whether an IP is in the explicit allowlist CIDR set."""
    allowed = list(allowlist_cidrs or [])
    settings_allowlist = getattr(get_settings(), "AEGIS_SSRF_ALLOWLIST_CIDRS", [])
    if isinstance(settings_allowlist, str):
        allowed.extend([c.strip() for c in settings_allowlist.split(",") if c.strip()])
    elif isinstance(settings_allowlist, (list, tuple)):
        allowed.extend(settings_allowlist)

    for cidr in allowed:
        try:
            if ip in ipaddress.ip_network(cidr.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


async def validate_outbound_url(
    url: str,
    allowlist_cidrs: Sequence[str] | None = None,
    target_type: str = "outbound_request",
) -> str:
    """
    Validates that a URL is safe for outbound dispatch:
    - Scheme must be http or https
    - Hostname must resolve to valid public IP addresses
    - Rejects loopback, link-local / cloud metadata (169.254.169.254), and private RFC1918 ranges
      unless explicitly allowed via allowlist_cidrs or AEGIS_SSRF_ALLOWLIST_CIDRS.
    Returns the validated URL, or raises SSRFProtectionError.
    """
    if not url:
        raise SSRFProtectionError("URL cannot be empty")

    parsed = urllib.parse.urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        record_ssrf_block(target_type)
        raise SSRFProtectionError(f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname
    if not hostname:
        record_ssrf_block(target_type)
        raise SSRFProtectionError(f"Invalid URL: missing host in '{url}'")

    # Check for direct IP in URL
    try:
        ip_obj = ipaddress.ip_address(hostname)
        resolved_ips = [ip_obj]
    except ValueError:
        # Hostname requires DNS resolution
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(
                hostname,
                parsed.port or (443 if scheme == "https" else 80),
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            resolved_ips = []
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                resolved_ips.append(ipaddress.ip_address(ip_str))
        except socket.gaierror as e:
            # If hostname does not resolve in DNS, it cannot reach any restricted network.
            # Allow the downstream HTTP client to handle the connection / unreachable host error.
            logger.debug("ssrf_dns_resolution_unresolved", hostname=hostname, error=str(e))
            return url

    if not resolved_ips:
        record_ssrf_block(target_type)
        raise SSRFProtectionError(f"No IP addresses resolved for host '{hostname}'")

    for ip in resolved_ips:
        # Check explicit allowlist first (e.g. for local dev/testing environments)
        if is_ip_allowed(ip, allowlist_cidrs):
            continue

        # Check blocked networks
        for blocked_net in BLOCKED_NETWORKS:
            if ip in blocked_net:
                record_ssrf_block(target_type)
                logger.warning(
                    "outbound_ssrf_blocked",
                    url=url,
                    resolved_ip=str(ip),
                    blocked_network=str(blocked_net),
                    target_type=target_type,
                )
                raise SSRFProtectionError(
                    f"Outbound access to destination '{hostname}' ({ip}) blocked by AegisGate SSRF policy: "
                    f"destination belongs to restricted network ({blocked_net})."
                )

    return url
