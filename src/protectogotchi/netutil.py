from __future__ import annotations

from ipaddress import ip_address


def is_relevant_neighbor(ip: str, mac: str) -> bool:
    try:
        parsed_ip = ip_address(ip)
    except ValueError:
        return False

    if parsed_ip.is_multicast or parsed_ip.is_unspecified or parsed_ip.is_link_local:
        return False

    normalized = mac.lower()
    if normalized == "ff:ff:ff:ff:ff:ff":
        return False

    first_octet = normalized.split(":", 1)[0]
    try:
        first_value = int(first_octet, 16)
    except ValueError:
        return False

    return (first_value & 1) == 0
