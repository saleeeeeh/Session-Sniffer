"""Module for checking support for broadcast and multicast capture filters on a specified network interface using tshark."""

# Standard Python Libraries
import subprocess
from pathlib import Path


def check_broadcast_multicast_support(tshark_path: Path, interface: str):
    """Check if the given network interface supports 'broadcast' and 'multicast' capture filters using tshark.

    Args:
        tshark_path (Path): Path to the tshark executable.
        interface (str): The name of the network interface to check.

    Returns:
        tuple: A tuple where the first value indicates support for 'broadcast',
               and the second indicates support for 'multicast' capture filters.
    """

    def run_tshark_filter_test(tshark_filter: str):
        """Run tshark with a given capture filter and return whether it was successful.

        Args:
            tshark_filter (str): The capture filter to test (e.g. "broadcast" or "multicast").

        Returns:
            bool: True if tshark ran successfully with the given filter, False otherwise.
        """
        cmd = [
            str(tshark_path),
            "-i", interface,
            "-f", tshark_filter,
            "-a", "duration:0",
            "-Q",
        ]
        try:
            subprocess.run(cmd, capture_output=True, check=True, text=True)
        except subprocess.CalledProcessError:
            return False
        return True

    return (run_tshark_filter_test("broadcast"), run_tshark_filter_test("multicast"))
