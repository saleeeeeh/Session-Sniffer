"""This module interacts with Windows Management Instrumentation (WMI) to retrieve network adapter details and related IP configuration data.

It uses two WMI namespaces: 'root/StandardCimv2' for modern CIM-based network data and 'root/Cimv2' for legacy management data.
"""

# Standard Python Libraries
import wmi
from wmi import _wmi_namespace


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


def iterate_project_network_neighbor_details():
    """Iterate project required network neighbor details from MSFT_NetNeighbor (standard CIMv2-based).

    Yields:
        - InterfaceIndex (int): The index of the network interface.
        - IPAddress (str | None): The IP address of the network neighbor.
        - LinkLayerAddress (str | None): The MAC address of the network neighbor.

    Raises:
        TypeError: If any of the returned WMI object is of an unexpected type.
    """
    for net_neighbor in standard_cimv2_namespace.query("SELECT InterfaceIndex, IPAddress, LinkLayerAddress FROM MSFT_NetNeighbor WHERE AddressFamily = 2"):  # https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-netneighbor
        if not isinstance(net_neighbor.InterfaceIndex, int):
            raise TypeError(f'Expected "int", got "{type(net_neighbor.InterfaceIndex).__name__}"')
        if not isinstance(net_neighbor.IPAddress, (str, type(None))):
            raise TypeError(f'Expected "str | None", got "{type(net_neighbor.IPAddress).__name__}"')
        if not isinstance(net_neighbor.LinkLayerAddress, (str, type(None))):
            raise TypeError(f'Expected "str | None", got "{type(net_neighbor.LinkLayerAddress).__name__}"')

        yield net_neighbor.InterfaceIndex, net_neighbor.IPAddress, net_neighbor.LinkLayerAddress


def iterate_project_network_adapter_details():
    """Iterate project required network adapter details from MSFT_NetAdapter (standard CIMv2-based).

    Yields:
        - InterfaceIndex (int): The index of the network interface.
        - Name (str): The name of the network adapter.
        - InterfaceDescription (str | None): Adapter description, if available.
        - State (int | None): The operational state of the network adapter.
        - PermanentAddress (str | None): The permanent MAC address of the network adapter.

    Raises:
        TypeError: If any of the returned WMI object is of an unexpected type.
    """
    for net_adapter in standard_cimv2_namespace.query("SELECT InterfaceIndex, Name, InterfaceDescription, State, PermanentAddress FROM MSFT_NetAdapter"):  # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
        if not isinstance(net_adapter.InterfaceIndex, int):
            raise TypeError(f'Expected "int" object, got "{type(net_adapter.InterfaceIndex).__name__}"')
        if not isinstance(net_adapter.Name, str):
            raise TypeError(f'Expected "str" object, got "{type(net_adapter.Name).__name__}"')
        if not isinstance(net_adapter.InterfaceDescription, (str, type(None))):
            raise TypeError(f'Expected "str | None" object, got "{type(net_adapter.InterfaceDescription).__name__}"')
        if not isinstance(net_adapter.state, (int, type(None))):
            raise TypeError(f'Expected "int | None" object, got "{type(net_adapter.state).__name__}"')
        if not isinstance(net_adapter.PermanentAddress, (str, type(None))):
            raise TypeError(f'Expected "str | None" object, got "{type(net_adapter.PermanentAddress).__name__}"')

        yield net_adapter.InterfaceIndex, net_adapter.Name, net_adapter.InterfaceDescription, net_adapter.state, net_adapter.PermanentAddress


def iterate_project_legacy_network_adapter_details():
    """Iterate project required network adapter details from Win32_NetworkAdapter (legacy CIMv2-based).

    Yields:
        - InterfaceIndex (int): The index of the network interface.
        - NetConnectionID (str): The name of the network adapter.
        - Description (str | None): Adapter description, if available.
        - MACAddress (str | None): The MAC address of the network adapter.
        - Manufacturer (str | None): The manufacturer of the network adapter.

    Raises:
        TypeError: If any of the returned WMI object is of an unexpected type.
    """
    for net_adapter in cimv2_namespace.query("SELECT InterfaceIndex, NetConnectionID, Description, MACAddress, Manufacturer FROM Win32_NetworkAdapter WHERE NetEnabled = True"):  # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapter
        if not isinstance(net_adapter.InterfaceIndex, int):
            raise TypeError(f'Expected "int" object, got "{type(net_adapter.InterfaceIndex).__name__}"')
        if not isinstance(net_adapter.NetConnectionID, str):
            raise TypeError(f'Expected "str" object, got "{type(net_adapter.NetConnectionID).__name__}"')
        if not isinstance(net_adapter.Description, (str, type(None))):
            raise TypeError(f'Expected "str | None" object, got "{type(net_adapter.Description).__name__}"')
        if not isinstance(net_adapter.MACAddress, (str, type(None))):
            raise TypeError(f'Expected "str | None" object, got "{type(net_adapter.MACAddress).__name__}"')
        if not isinstance(net_adapter.Manufacturer, (str, type(None))):
            raise TypeError(f'Expected "str | None" object, got "{type(net_adapter.Manufacturer).__name__}"')

        yield net_adapter.InterfaceIndex, net_adapter.NetConnectionID, net_adapter.Description, net_adapter.MACAddress, net_adapter.Manufacturer


def iterate_project_network_ip_details():
    """Yield project required network adapter IP configuration details from MSFT_NetIPAddress (standard CIMv2-based).

    Yields:
        - InterfaceIndex (int): The index of the network interface.
        - InterfaceAlias (str): Adapter description, if available.
        - IPv4Address (str | None): The IPv4 address assigned to the interface, or None.

    Raises:
        TypeError: If any of the returned WMI object is of an unexpected type.
    """
    for net_ip in standard_cimv2_namespace.query("SELECT InterfaceIndex, InterfaceAlias, IPv4Address FROM MSFT_NetIPAddress WHERE AddressFamily = 2"):  # https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-netipaddress
        if not isinstance(net_ip.InterfaceIndex, int):
            raise TypeError(f'Expected "int" object, got "{type(net_ip.InterfaceIndex).__name__}"')
        if not isinstance(net_ip.InterfaceAlias, str):
            raise TypeError(f'Expected "str" object, got "{type(net_ip.InterfaceAlias).__name__}"')
        if not isinstance(net_ip.IPv4Address, (str, type(None))):
            raise TypeError(f'Expected "str | None" object, got "{type(net_ip.IPv4Address).__name__}"')

        yield net_ip.InterfaceIndex, net_ip.InterfaceAlias, net_ip.IPv4Address


def iterate_project_legacy_network_ip_details():
    """Yield project required legacy network adapter IP configuration details from Win32_NetworkAdapterConfiguration (legacy CIMv2-based).

    Yields:
        - InterfaceIndex (int): The index of the network interface.
        - Description (str | None): Adapter description, if available.
        - MACAddress (str | None): The MAC address of the network adapter.
        - IPAddress (tuple[str, ...] | None): Tuple of IP addresses assigned, or None.
        - IPEnabled (bool | None): True if TCP/IP is enabled, otherwise False or None.

    Raises:
        TypeError: If any of the returned WMI object is of an unexpected type.
    """
    for net_ip in cimv2_namespace.query("SELECT InterfaceIndex, Description, MACAddress, IPAddress, IPEnabled FROM Win32_NetworkAdapterConfiguration"):  # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapterconfiguration
        if not isinstance(net_ip.InterfaceIndex, int):
            raise TypeError(f'Expected "int" object, got "{type(net_ip.InterfaceIndex).__name__}"')
        if not isinstance(net_ip.Description, (str, type(None))):
            raise TypeError(f'Expected "str | None" object, got "{type(net_ip.Description).__name__}"')
        if not isinstance(net_ip.MACAddress, (str, type(None))):
            raise TypeError(f'Expected "str | None" object, got "{type(net_ip.MACAddress).__name__}"')
        if not isinstance(net_ip.IPAddress, (tuple, type(None))):
            raise TypeError(f'Expected "tuple | None" object, got "{type(net_ip.IPAddress).__name__}"')
        if net_ip.IPAddress and not all(isinstance(ip, str) for ip in net_ip.IPAddress):
            raise TypeError("Expected all items in 'IPAddress' to be of type 'str'")
        if not isinstance(net_ip.IPEnabled, (bool, type(None))):
            raise TypeError(f'Expected "bool | None" object, got "{type(net_ip.IPEnabled).__name__}"')

        ip_address: tuple[str, ...] | None = net_ip.IPAddress  # fixes type hint

        yield net_ip.InterfaceIndex, net_ip.Description, net_ip.MACAddress, ip_address, net_ip.IPEnabled
