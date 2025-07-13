"""Module for packet capture using TShark, including packet processing and handling of TShark crashes."""
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic.dataclasses import dataclass

from modules.constants.external import LOCAL_TZ
from modules.constants.standalone import MAX_PORT, MIN_PORT


class TSharkProcessingError(ValueError):
    """Base class for TShark packet parsing errors."""


class UnexpectedFieldCountError(TSharkProcessingError):
    """"Raised when the number of fields in TShark output is unexpected."""

    def __init__(self, expected: int, actual: int, fields: tuple[str, ...]):
        """Initialize the UnexpectedFieldCountError exception."""
        super().__init__(
            f"Unexpected number of fields in TShark output. "
            f'Expected "{expected}", got "{actual}": "{fields}"',
        )


class MissingRequiredFieldsError(TSharkProcessingError):
    """Raised when required fields are missing in TShark output."""

    def __init__(self, fields: tuple[str, ...]):
        """Initialize the MissingRequiredFieldsError exception."""
        super().__init__(
            f"One of the required first three fields is empty. Fields: {fields}",
        )


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


@dataclass(frozen=True, slots=True)
class PacketFields:
    frame_time: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str


@dataclass(frozen=True, slots=True)
class Frame:
    packet_datetime: datetime

    @classmethod
    def from_epoch(cls, time_epoch: str):
        return cls(packet_datetime=converts_tshark_packet_timestamp_to_datetime_object(time_epoch))


@dataclass(frozen=True, slots=True)
class IP:
    src: str
    dst: str


@dataclass(frozen=True, slots=True)
class UDP:
    srcport: int
    dstport: int


@dataclass(frozen=True, slots=True)
class Packet:
    frame: Frame
    ip: IP
    udp: UDP

    @classmethod
    def from_fields(cls, fields: PacketFields):
        """"Create a Packet object from TShark output fields.

        Args:
            fields (PacketFields): A named tuple containing the packet fields.

        Returns:
            Packet: A Packet object containing the parsed fields.

        Raises:
            InvalidPortFormatError: If the source or destination ports are not digits.
            InvalidPortNumberError: If the source or destination ports are not valid.
        """
        if not fields.src_port.isdecimal():
            raise InvalidPortFormatError(fields.src_port)
        src_port = int(fields.src_port)

        if not fields.dst_port.isdecimal():
            raise InvalidPortFormatError(fields.dst_port)
        dst_port = int(fields.dst_port)

        if not MIN_PORT <= src_port <= MAX_PORT:
            raise InvalidPortNumberError(src_port)
        if not MIN_PORT <= dst_port <= MAX_PORT:
            raise InvalidPortNumberError(dst_port)

        return cls(
            Frame.from_epoch(fields.frame_time),
            IP(fields.src_ip, fields.dst_ip),
            UDP(src_port, dst_port),
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

        self._EXPECTED_PACKET_FIELDS = 5

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
                PacketFields: A named tuple containing the packet fields.

            Raises:
                UnexpectedFieldCountError: If the number of fields in the line is unexpected.
                MissingRequiredFieldsError: If any of the required fields are missing.
                InvalidPortFormatError: If the source or destination ports are not digits.
                InvalidPortNumberError: If the source or destination ports are not valid.
            """
            # Split the line into fields and limit the split based on the expected number of fields
            fields = tuple(field.strip() for field in line.split("|", self._EXPECTED_PACKET_FIELDS))
            if len(fields) != self._EXPECTED_PACKET_FIELDS:
                raise UnexpectedFieldCountError(self._EXPECTED_PACKET_FIELDS, len(fields), fields)

            # Ensure the first three fields are not empty
            if any(not field for field in fields[:3]):
                raise MissingRequiredFieldsError(fields)

            # TODO(BUZZARDGTA): It would be ideal to retain these packets instead of discarding them.
            # Displaying "None" in the Port field should be supported at some point.
            # Allow the last two fields (source and destination ports) to be empty.
            if "" in {fields[-2], fields[-1]}:
                print(f"Source or destination port is missing. Packet ignored: [{line}]")
                return None  # Skip processing if either of the last two fields is empty

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
                if process.returncode != 0:
                    raise TSharkCrashExceptionError(process.returncode, stderr_output)


def converts_tshark_packet_timestamp_to_datetime_object(packet_frame_time_epoch: str):
    dt_utc = datetime.fromtimestamp(float(packet_frame_time_epoch), tz=UTC)
    return dt_utc.astimezone(LOCAL_TZ)
