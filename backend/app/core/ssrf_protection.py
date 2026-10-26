"""SSRF and Destination Security Guard.

Validates that destinations, URLs, and hostnames never resolve to:
- RFC 1918 Private networks
- Loopback addresses
- Link-local / Cloud metadata endpoints (169.254.169.254, metadata.google.internal, etc.)
- Carrier-grade NAT (100.64.0.0/10)
- Reserved documentation/test networks
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, List
from backend.app.core.config import settings

# Explicit blocked metadata hosts and IPs
BLOCKED_SPECIAL_HOSTS = {
    "metadata.google.internal",
    "instance-data",
    "metadata",
    "169.254.169.254",
    "localhost",
}

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 blocked ranges
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("ff00::/8"),
]


class SSRFValidationError(Exception):
    """Raised when a target fails SSRF safety validation."""
    pass


def extract_host(target: str) -> str:
    """Extract host string from a URL, domain, or IP target."""
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
    else:
        # Check if it has a port like host:8080 or path
        host = target.split("/")[0].split(":")[0]
    return host.strip().lower()


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check if an IP address falls within prohibited ranges."""
    for network in BLOCKED_IP_NETWORKS:
        if ip in network:
            return True, f"IP {ip} falls into restricted network range {network}"
    if ip.is_private and settings.BLOCK_PRIVATE_NETWORKS:
        return True, f"IP {ip} is in a private network"
    if ip.is_loopback:
        return True, f"IP {ip} is a loopback address"
    if ip.is_link_local and settings.BLOCK_CLOUD_METADATA:
        return True, f"IP {ip} is a link-local address (potential cloud metadata)"
    return False, ""


def validate_destination_safety(target: str) -> Tuple[bool, str, List[str]]:
    """Strictly validate whether a destination is safe to contact.
    
    Resolves DNS and verifies all resolved IP addresses.
    Returns: (is_safe, error_reason, resolved_ips)
    """
    host = extract_host(target)
    if not host:
        return False, "Target host is empty or invalid", []

    if host in BLOCKED_SPECIAL_HOSTS:
        return False, f"Target host '{host}' is explicitly blocked (metadata/loopback endpoint)", []

    # Check if target is a raw IP literal
    try:
        ip_obj = ipaddress.ip_address(host)
        blocked, reason = is_ip_blocked(ip_obj)
        if blocked:
            return False, reason, [str(ip_obj)]
        return True, "", [str(ip_obj)]
    except ValueError:
        # It's a hostname / domain name, resolve via DNS
        pass

    try:
        # Resolve all IPv4 and IPv6 addresses for the host
        addr_info = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        resolved_ips = list({item[4][0] for item in addr_info})
        if not resolved_ips:
            return False, f"Host '{host}' could not be resolved to any IP address", []

        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                blocked, reason = is_ip_blocked(ip_obj)
                if blocked:
                    return False, f"Host '{host}' resolves to restricted IP: {reason}", resolved_ips
            except ValueError:
                return False, f"Invalid IP returned for host {host}: {ip_str}", resolved_ips

        return True, "", resolved_ips
    except socket.gaierror as e:
        return False, f"DNS resolution failed for host '{host}': {str(e)}", []
    except Exception as e:
        return False, f"Error validating destination '{host}': {str(e)}", []
