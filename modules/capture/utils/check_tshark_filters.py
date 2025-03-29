"""
Module for checking support for broadcast and multicast capture filters on a specified network interface using tshark.
"""

# Standard Python Libraries
import subprocess
from typing import Optional, NamedTuple
from pathlib import Path


class InterfaceSupportResult(NamedTuple):
    interface: str
    broadcast_supported: bool
    multicast_supported: bool
    broadcast_error: Optional[str]
    multicast_error: Optional[str]


def check_broadcast_multicast_support(tshark_path: Path, interface: str):
    """
    Check if the given network interface supports broadcast or multicast capture filters in tshark.

    Args:
        tshark_path: Path to the tshark executable.
        interface: The name of the network interface to check.

    Returns:
        A named tuple containing test results.
    """

    def run_tshark_test(filter_type: str):
        """Runs tshark with a given filter and returns whether it was successful."""
        cmd = [
            str(tshark_path),
            "-i", interface,
            "-f", filter_type,
            "-a", "duration:0",
            "-Q"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.returncode == 0, result.stderr.strip() if result.returncode != 0 else None

    broadcast_supported, broadcast_error = run_tshark_test("broadcast")
    multicast_supported, multicast_error = run_tshark_test("multicast")

    return InterfaceSupportResult(
        interface=interface,
        broadcast_supported=broadcast_supported,
        multicast_supported=multicast_supported,
        broadcast_error=broadcast_error,
        multicast_error=multicast_error
    )
