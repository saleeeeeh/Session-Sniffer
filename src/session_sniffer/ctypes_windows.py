"""Common Windows ctypes structures and COM helper functions."""

import ctypes
import ctypes.wintypes


class WindowsGuid(ctypes.Structure):
    """ctypes definition for Windows GUID structure."""

    _fields_ = [
        ('Data1', ctypes.wintypes.DWORD),
        ('Data2', ctypes.wintypes.WORD),
        ('Data3', ctypes.wintypes.WORD),
        ('Data4', ctypes.c_ubyte * 8),
    ]


def release_com_interface(pointer: ctypes.wintypes.LPVOID) -> None:
    """Releases a COM interface pointer via its IUnknown vtable."""
    if pointer:
        vtable = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        release_function = ctypes.WINFUNCTYPE(ctypes.wintypes.ULONG, ctypes.wintypes.LPVOID)(vtable[2])
        release_function(pointer)
