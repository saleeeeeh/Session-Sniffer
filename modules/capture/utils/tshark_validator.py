"""
Module for validating TShark executable paths and versions, including exception handling for invalid versions.
"""

# Standard Python Libraries
import subprocess
from pathlib import Path
from typing import NamedTuple

# Local Python Libraries (Included with Project)
from modules.constants.standalone import TSHARK_RECOMMENDED_FULL_VERSION


class TSharkNotFoundException(Exception):
    """Exception raised when TShark is not found at the specified path."""


class TSharkVersionNotFoundException(Exception):
    """Exception raised when TShark's version cannot be determined."""


class InvalidTSharkVersionException(Exception):
    def __init__(self, path: Path, version: str):
        self.path = path
        self.version = version
        self.message = f"Invalid TShark version: {version}"
        super().__init__(self.message)


class TSharkValidationResult(NamedTuple):
    path: Path
    version: str


def validate_tshark_path(tshark_path: Path):
    """
    Validate the path and version of the given tshark executable.

    Args:
        tshark_path: The path of the tshark executable.

    Raises:
        TSharkNotFoundException: If TShark is not found at the specified location.
        TSharkVersionNotFoundException: If the TShark version cannot be determined.
        InvalidTSharkVersionException: If the found TShark version is unsupported.
    """

    def get_tshark_version(path: Path):
        """Attempts to retrieve TShark's version from the given path."""
        try:
            result = subprocess.check_output([path, '--version'], text=True).splitlines()
            return result[0] if result else None
        except subprocess.CalledProcessError:
            return None

    if not tshark_path.is_file():
        raise TSharkNotFoundException

    tshark_version = get_tshark_version(tshark_path)
    if not tshark_version:
        raise TSharkVersionNotFoundException

    if tshark_version != TSHARK_RECOMMENDED_FULL_VERSION:
        raise InvalidTSharkVersionException(tshark_path, tshark_version)

    return TSharkValidationResult(tshark_path, tshark_version)
