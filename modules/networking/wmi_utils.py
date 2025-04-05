"""This module interacts with Windows Management Instrumentation (WMI) to retrieve network adapter details and related IP configuration data.

It uses two WMI namespaces: 'root/StandardCimv2' for modern CIM-based network data and 'root/Cimv2' for legacy management data.
"""

# Standard Python Libraries
import wmi
from wmi import _wmi_namespace, _wmi_object


# Initializing two WMI namespaces: "root/StandardCimv2" for modern CIM-based management with up-to-date network adapter data, and "root/Cimv2"
# for legacy management, necessary to retrieve properties like "Manufacturer" and "NetEnabled" not available in the newer namespace.
#
# Both namespaces are required for complete network adapter information.
standard_cimv2_namespace: _wmi_namespace = wmi.WMI(namespace="root/StandardCimv2")
if not isinstance(standard_cimv2_namespace, _wmi_namespace):
    raise TypeError(f'Expected "_wmi_namespace" object, got "{type(standard_cimv2_namespace).__name__}"')

cimv2_namespace: _wmi_namespace = wmi.WMI(namespace="root/Cimv2")
if not isinstance(cimv2_namespace, _wmi_namespace):
    raise TypeError(f'Expected "_wmi_namespace" object, got "{type(cimv2_namespace).__name__}"')


def iterate_network_neighbor_details(**kwargs):
    """Yields project requiered network neighbor details from MSFT_NetNeighbor (standard CIM v2 based)."""
    net_neighbor_details: list[_wmi_object] = standard_cimv2_namespace.MSFT_NetNeighbor(**kwargs)  # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
    if not isinstance(net_neighbor_details, list):
        raise TypeError(f'Expected "list", got "{type(net_neighbor_details).__name__}"')

    for net_neighbor in net_neighbor_details:
        if not isinstance(net_neighbor, _wmi_object):
            raise TypeError(f'Expected "_wmi_object", got "{type(net_neighbor).__name__}"')

        interface_index = getattr(net_neighbor, "InterfaceIndex", None)
        if not isinstance(interface_index, int):
            raise TypeError(f'Expected "int", got "{type(interface_index).__name__}"')

        ip_address = getattr(net_neighbor, "IPAddress", None)
        if not isinstance(ip_address, str):
            raise TypeError(f'Expected "str", got "{type(ip_address).__name__}"')

        mac_address = getattr(net_neighbor, "LinkLayerAddress", None)
        if not isinstance(mac_address, str):
            raise TypeError(f'Expected "str", got "{type(mac_address).__name__}"')

        yield interface_index, ip_address, mac_address


def iterate_legacy_network_adapter_details(**kwargs):
    """Yields project requiered network adapter details from Win32_NetworkAdapter (legacy CIM v2 based)."""
    net_adapter_details: list[_wmi_object] = cimv2_namespace.Win32_NetworkAdapter(**kwargs)  # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapter
    if not isinstance(net_adapter_details, list):
        raise TypeError(f'Expected "list", got "{type(net_adapter_details).__name__}"')

    for net_adapter in net_adapter_details:
        if not isinstance(net_adapter, _wmi_object):
            raise TypeError(f'Expected "_wmi_object", got "{type(net_adapter).__name__}"')

        interface_index = getattr(net_adapter, "InterfaceIndex", None)
        if not isinstance(interface_index, int):
            raise TypeError(f'Expected "int" object, got "{type(interface_index).__name__}"')

        manufacturer = getattr(net_adapter, "Manufacturer", None)
        if manufacturer is None:
            continue
        if not isinstance(manufacturer, str):
            raise TypeError(f'Expected "str" object, got "{type(manufacturer).__name__}"')

        yield interface_index, manufacturer


def iterate_network_adapter_details(**kwargs):
    """Yields project requiered network adapter details from MSFT_NetAdapter (standard CIM v2 based)."""
    net_adapter_details: list[_wmi_object] = standard_cimv2_namespace.MSFT_NetAdapter(**kwargs)  # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
    if not isinstance(net_adapter_details, list):
        raise TypeError(f'Expected "list", got "{type(net_adapter_details).__name__}"')

    for net_adapter in net_adapter_details:
        if not isinstance(net_adapter, _wmi_object):
            raise TypeError(f'Expected "_wmi_object", got "{type(net_adapter).__name__}"')

        name = getattr(net_adapter, "Name", None)
        if not isinstance(name, str):
            raise TypeError(f'Expected "str" object, got "{type(name).__name__}"')

        interface_description = getattr(net_adapter, "InterfaceDescription", None)
        if not isinstance(interface_description, str):
            raise TypeError(f'Expected "str" object, got "{type(interface_description).__name__}"')

        state = getattr(net_adapter, "state", None)
        if not isinstance(state, int):
            raise TypeError(f'Expected "int" object, got "{type(state).__name__}"')

        interface_index = getattr(net_adapter, "InterfaceIndex", None)
        if interface_index is None:
            continue
        if not isinstance(interface_index, int):
            raise TypeError(f'Expected "int" object, got "{type(interface_index).__name__}"')

        permanent_address = getattr(net_adapter, "PermanentAddress", None)
        if permanent_address is None:
            continue
        if not isinstance(permanent_address, str):
            raise TypeError(f'Expected "str" object, got "{type(permanent_address).__name__}"')

        yield name, interface_description, state, interface_index, permanent_address


def iterate_legacy_network_ip_details(**kwargs):
    """Yields project requiered network adapter ip details from Win32_NetworkAdapterConfiguration (legacy CIM v2 based)."""
    net_ip_details: list[_wmi_object] = cimv2_namespace.Win32_NetworkAdapterConfiguration(**kwargs)  # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapterconfiguration
    if not isinstance(net_ip_details, list):
        raise TypeError(f'Expected "list", got "{type(net_ip_details).__name__}"')

    for net_ip in net_ip_details:
        if not isinstance(net_ip, _wmi_object):
            raise TypeError(f'Expected "_wmi_object", got "{type(net_ip).__name__}"')

        interface_index = getattr(net_ip, "InterfaceIndex", None)
        if not isinstance(interface_index, int):
            raise TypeError(f'Expected "int" object, got "{type(interface_index).__name__}"')

        ip_enabled = getattr(net_ip, "IPEnabled", None)
        if not isinstance(ip_enabled, bool):
            raise TypeError(f'Expected "bool" object, got "{type(ip_enabled).__name__}"')

        yield interface_index, ip_enabled


def iterate_network_ip_details(**kwargs):
    """Yields project requiered network adapter ip details from MSFT_NetIPAddress (standard CIM v2 based)."""
    net_ip_details: list[_wmi_object] = standard_cimv2_namespace.MSFT_NetIPAddress(**kwargs)  # https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-netipaddress
    if not isinstance(net_ip_details, list):
        raise TypeError(f'Expected "list", got "{type(net_ip_details).__name__}"')

    for net_ip in net_ip_details:
        if not isinstance(net_ip, _wmi_object):
            raise TypeError(f'Expected "_wmi_object", got "{type(net_ip).__name__}"')

        interface_index = getattr(net_ip, "InterfaceIndex", None)
        if not isinstance(interface_index, int):
            raise TypeError(f'Expected "int" object, got "{type(interface_index).__name__}"')

        ip_address = getattr(net_ip, "IPAddress", None)
        if ip_address is None:
            continue
        if not isinstance(ip_address, str):
            raise TypeError(f'Expected "str" object, got "{type(ip_address).__name__}"')

        yield interface_index, ip_address
