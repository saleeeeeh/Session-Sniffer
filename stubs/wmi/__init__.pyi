from typing import Any


class _wmi_object:
    InterfaceIndex: Any
    IPAddress: Any
    LinkLayerAddress: Any
    Name: Any
    InterfaceDescription: Any
    state: Any
    NetConnectionID: Any
    Description: Any
    MACAddress: Any
    Manufacturer: Any
    InterfaceAlias: Any
    IPv4Address: Any
    IPEnabled: Any


class _wmi_namespace:
    def query(self, wql: str) -> list[_wmi_object]: ...


def WMI(*, namespace: str) -> _wmi_namespace: ...


__all__ = ['WMI', '_wmi_namespace', '_wmi_object']
