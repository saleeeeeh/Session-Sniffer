# Standard Python Libraries
from pathlib import Path
from typing import NamedTuple


class TSharkNotFoundException(Exception):
    """Exception raised when TShark is not found at the specified path."""
    pass

class TSharkVersionNotFoundException(Exception):
    """Exception raised when TShark's version cannot be determined."""
    pass

class InvalidTSharkVersionException(Exception):
    def __init__(self, path: Path, version: str):
        self.path = path
        self.version = version
        self.message = f"Invalid TShark version: {version}"
        super().__init__(self.message)


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
    import subprocess
    from Modules.constants.standalone import TSHARK_RECOMMENDED_FULL_VERSION, TITLE

    class TSharkValidationResult(NamedTuple):
        path: Path
        version: str

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


def is_npcap_installed():
    import subprocess

    return subprocess.run(["sc", "query", "npcap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
