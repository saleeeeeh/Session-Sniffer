"""Module for packet capture using TShark, including packet processing and handling of TShark crashes."""
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic.dataclasses import dataclass

from modules.constants.external import LOCAL_TZ
from modules.constants.standalone import MAX_PORT, MIN_PORT
from modules.networking.utils import is_ipv4_address

_EXPECTED_TSHARK_PACKET_FIELD_COUNT = 5


class TSharkProcessingError(ValueError):
    """Base class for TShark packet parsing errors."""


class UnexpectedFieldCountError(TSharkProcessingError):
    """"Raised when the number of fields in TShark output is unexpected."""

    def __init__(self, actual: int, fields: tuple[str, ...]):
        """Initialize the UnexpectedFieldCountError exception."""
        super().__init__(
            f"Unexpected number of fields in TShark output. "
            f'Expected "{_EXPECTED_TSHARK_PACKET_FIELD_COUNT}", got "{actual}": "{fields}"',
        )


class MissingRequiredFieldsError(TSharkProcessingError):
    """Raised when required fields are missing in TShark output."""

    def __init__(self, fields: tuple[str, ...]):
        """Initialize the MissingRequiredFieldsError exception."""
        super().__init__(
            f"One of the required first three fields is empty. Fields: {fields}",
        )


class InvalidIPv4AddressError(TSharkProcessingError):
    """Raised when the source or destination IP addresses are not valid IPv4 addresses."""

    def __init__(self, ip: str):
        """Initialize the InvalidIPv4AddressError exception."""
        super().__init__(f"Invalid IPv4 address: {ip}. IP must be a valid IPv4 address.")


class InvalidPortFormatError(TSharkProcessingError):
    """"Raised when source or destination ports are not digits."""

    def __init__(self, port: str):
        """Initialize the InvalidPortFormatError exception."""
        super().__init__(f"Invalid port format: {port}. Port must be a number.")


class InvalidPortNumberError(TSharkProcessingError):
    """Raised when source or destination ports are not valid."""

    def __init__(self, port: int):
        """Initialize the InvalidPortNumberError exception."""
        super().__init__(f"Invalid port number: {port}. Port must be a number between {MIN_PORT} and {MAX_PORT}.")


class TSharkCrashExceptionError(Exception):
    """Exception raised when TShark crashes.

    Attributes:
        returncode (int): The return code of the TShark process.
        stderr_output (str): The standard error output from TShark.
    """

    def __init__(self, returncode: int, stderr_output: str):
        """Initialize the exception with the return code and standard error output.

        Args:
            returncode (int): The return code of the TShark process.
            stderr_output (str): The standard error output from TShark.
        """
        super().__init__(f"TShark crashed with return code {returncode}: {stderr_output}")


def _parse_and_validate_port(port_str: str, /):
    if not port_str.isascii() or not port_str.isdecimal():
        raise InvalidPortFormatError(port_str)
    port = int(port_str)
    if not MIN_PORT <= port <= MAX_PORT:
        raise InvalidPortNumberError(port)
    return port


def _parse_and_validate_ip(ip: str, /):
    if not is_ipv4_address(ip):
        raise InvalidIPv4AddressError(ip)
    return ip


def _convert_epoch_time_to_datetime(time_epoch: float, /):
    dt_utc = datetime.fromtimestamp(time_epoch, tz=UTC)
    return dt_utc.astimezone(LOCAL_TZ)


@dataclass(frozen=True, slots=True)
class PacketFields:
    time_epoch: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str


@dataclass(frozen=True, kw_only=True, slots=True)
class IP:
    src: str
    dst: str


@dataclass(frozen=True, kw_only=True, slots=True)
class Port:
    src: int
    dst: int


@dataclass(frozen=True, kw_only=True, slots=True)
class Packet:
    datetime: datetime
    ip: IP
    port: Port

    @classmethod
    def from_fields(cls, fields: PacketFields):
        """"Create a Packet object from TShark output fields.

        Args:
            fields (PacketFields): A named tuple containing the packet fields.

        Returns:
            Packet: A Packet object containing the parsed fields.

        Raises:
            InvalidIPv4AddressError: If the source or destination IP addresses are not valid IPv4 addresses.
            InvalidPortFormatError: If the source or destination ports are not digits.
            InvalidPortNumberError: If the source or destination ports are not valid.
        """
        return cls(
            datetime=_convert_epoch_time_to_datetime(float(fields.time_epoch)),
            ip=IP(
                src=_parse_and_validate_ip(fields.src_ip),
                dst=_parse_and_validate_ip(fields.dst_ip),
            ),
            port=Port(
                src=_parse_and_validate_port(fields.src_port),
                dst=_parse_and_validate_port(fields.dst_port),
            ),
        )


class PacketCapture:
    def __init__(
        self,
        *,
        interface: str,
        tshark_path: Path,
        capture_filter: str | None = None,
        display_filter: str | None = None,
    ):
        """Initialize the PacketCapture class.

        Args:
            interface (str): The network interface to capture packets from.
            tshark_path (Path): The path to the TShark executable.
            capture_filter (str | None): Optional capture filter for TShark.
            display_filter (str | None): Optional display filter for TShark.
        """
        self.interface = interface
        self.tshark_path = tshark_path
        self.capture_filter = capture_filter
        self.display_filter = display_filter

        self._tshark_cmd = (
            str(tshark_path),
            "-l", "-n", "-Q",
            "--log-level", "critical",
            "-B", "1",
            "-i", interface,
            *(("-f", capture_filter) if capture_filter else ()),
            *(("-Y", display_filter) if display_filter else ()),
            "-T", "fields",
            "-E", "separator=|",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
        )
        self._tshark_process: subprocess.Popen[str] | None = None

    def apply_on_packets(self, callback: Callable[[Packet], None]):
        """Apply a callback function to each captured packet."""
        for packet in self._capture_packets():
            callback(packet)

    def _capture_packets(self):
        """Capture packets using TShark and process the output.

        Yields:
            Packet: A packet object containing the captured packet data.
        """

        def process_tshark_stdout(line: str):
            """Process a line of TShark output and return a PacketFields object.

            Args:
                line (str): A line of TShark output.

            Returns:
                (PacketFields | None): A named tuple containing the packet fields., or `None` if the packet is invalid.

            Raises:
                TSharkProcessingError: If IPs or ports are invalid or the number of fields in the line is unexpected.
            """
            # Split the line into fields and limit the split based on the expected number of fields
            fields = tuple(field.strip() for field in line.split("|", _EXPECTED_TSHARK_PACKET_FIELD_COUNT))
            if len(fields) != _EXPECTED_TSHARK_PACKET_FIELD_COUNT:
                raise UnexpectedFieldCountError(len(fields), fields)

            # Ensure the first three fields are not empty
            if any(not field for field in fields[:3]):
                raise MissingRequiredFieldsError(fields)

            # TODO(BUZZARDGTA): It would be ideal to retain these packets instead of discarding them.
            # Displaying "None" in the Port column should be supported at some point in the future development.
            # Skip processing if source or destination port is missing (last two fields)
            if not fields[-2] or not fields[-1]:
                print(f"Source or destination port is missing. Packet ignored: [{line}]")
                return None

            return PacketFields(*fields)

        with subprocess.Popen(
            self._tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        ) as process:
            self._tshark_process = process

            if process.stdout:
                # Iterate over stdout line by line as it is being produced
                for line in process.stdout:
                    packet_fields = process_tshark_stdout(line.rstrip())
                    if packet_fields is None:
                        continue

                    yield Packet.from_fields(packet_fields)

            # After stdout is done, check if there were any errors in stderr
            if process.stderr:
                stderr_output = process.stderr.read()
                if isinstance(process.returncode, int) and process.returncode:
                    raise TSharkCrashExceptionError(process.returncode, stderr_output)
