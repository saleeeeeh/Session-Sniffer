"""
Module for defining networking utility functions, including MAC address and IPv4 address operations.
"""

# Standard Python Libraries
from ipaddress import IPv4Address, AddressValueError

# Local Python Libraries (Included with Project)
from modules.constants.standard import RE_MAC_ADDRESS_PATTERN


def is_mac_address(mac_address: str):
    return bool(RE_MAC_ADDRESS_PATTERN.fullmatch(mac_address))


def sanitize_mac_address(mac_address: str):
    """Remove any separators from the MAC address and convert to uppercase."""
    return "".join(c for c in mac_address if c.isalnum()).upper()


def format_mac_address(mac_address: str, separator: str = ":"):
    """Format the MAC address using the specified separator (default: XX:XX:XX:XX:XX:XX)."""
    sanitized_mac = sanitize_mac_address(mac_address)
    return separator.join(sanitized_mac[i:i + 2] for i in range(0, len(sanitized_mac), 2))


def get_mac_oui(mac_address: str, separator: str = ""):
    """Extracts the OUI (first three hexadecimal pairs) from a MAC address and formats it with the specified separator."""
    sanitized_mac = sanitize_mac_address(mac_address)
    return separator.join(sanitized_mac[i:i + 2] for i in range(0, 6, 2))


def is_ipv4_address(ip_address: str):
    try:
        return IPv4Address(ip_address).version == 4
    except AddressValueError:
        return False


def is_private_device_ipv4(ip_address: str):
    return IPv4Address(ip_address).is_private


def is_valid_non_special_ipv4(ip_address: str):
    try:
        ipv4_obj = IPv4Address(ip_address)
    except AddressValueError:
        return False

    invalid_conditions = [
        ipv4_obj.version != 4,
        ipv4_obj.packed[-1] == 255,
        ipv4_obj.is_link_local,  # might wants to remove this
        ipv4_obj.is_loopback,
        ipv4_obj.is_reserved,
        ipv4_obj.is_unspecified,
        ipv4_obj.is_global,
        ipv4_obj.is_multicast
    ]

    if any(invalid_conditions):
        return False

    return True


def get_network_arp_cache():
    from modules.networking.wmi_utils import iterate_network_neighbor_details

    cached_arp_dict: dict[int, list[dict[str, str]]] = {}

    for interface_index, ip_address, mac_address in iterate_network_neighbor_details(AddressFamily=2):
        if None in (interface_index, ip_address, mac_address):
            continue

        # Append ARP info directly to the dictionary entry
        entry = {
            "ip_address": ip_address,
            "mac_address": mac_address
        }
        if entry not in cached_arp_dict.setdefault(interface_index, []):
            cached_arp_dict[interface_index].append(entry)

    return cached_arp_dict
