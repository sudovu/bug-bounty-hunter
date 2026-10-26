"""Unit Tests for SSRF and Destination Safety Protections."""
import ipaddress
import pytest
from backend.app.core.ssrf_protection import (
    validate_destination_safety,
    extract_host,
    is_ip_blocked
)


def test_extract_host():
    assert extract_host("https://api.example.com/v1/test") == "api.example.com"
    assert extract_host("http://example.com:8080/path") == "example.com"
    assert extract_host("sub.domain.com") == "sub.domain.com"
    assert extract_host("192.168.1.1:3000") == "192.168.1.1"


def test_blocked_private_ip_ranges():
    # RFC 1918 Private networks
    for ip_str in ["10.0.0.1", "172.16.5.10", "192.168.1.100"]:
        ip = ipaddress.ip_address(ip_str)
        blocked, reason = is_ip_blocked(ip)
        assert blocked is True
        assert "restricted network range" in reason or "private network" in reason


def test_blocked_loopback_and_metadata():
    # Loopback
    ip_loopback = ipaddress.ip_address("127.0.0.1")
    blocked, reason = is_ip_blocked(ip_loopback)
    assert blocked is True

    # Cloud metadata IP (AWS/GCP/Azure)
    ip_meta = ipaddress.ip_address("169.254.169.254")
    blocked, reason = is_ip_blocked(ip_meta)
    assert blocked is True


def test_destination_safety_direct_ip():
    # Direct loopback IP target
    safe, reason, _ = validate_destination_safety("http://127.0.0.1:8000")
    assert safe is False
    assert "restricted" in reason.lower() or "loopback" in reason.lower()

    # Cloud metadata target
    safe, reason, _ = validate_destination_safety("http://169.254.169.254/latest/meta-data/")
    assert safe is False

    # Special cloud metadata host
    safe, reason, _ = validate_destination_safety("metadata.google.internal")
    assert safe is False


def test_destination_safety_empty():
    safe, reason, _ = validate_destination_safety("")
    assert safe is False
