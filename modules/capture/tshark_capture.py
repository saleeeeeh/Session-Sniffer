"""Module for packet capture using TShark, including packet processing and handling of TShark crashes."""

# Standard Python Libraries
import subprocess
from pathlib import Path
from typing import NamedTuple
from collections.abc import Callable
from datetime import datetime

# Local Python Libraries (Included with Project)
from modules.constants.external import LOCAL_TZ


class PacketFields(NamedTuple):
    frame_time: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str


class TSharkCrashExceptionError(Exception):
    pass


class Frame:
    def __init__(self, time_epoch: str):
        self.datetime = converts_tshark_packet_timestamp_to_datetime_object(time_epoch)


class IP:
    def __init__(self, src: str, dst: str):
        self.src = src
        self.dst = dst


class UDP:
    def __init__(self, srcport: str, dstport: str):
        self.srcport = int(srcport)
        self.dstport = int(dstport)


class Packet:
    def __init__(self, fields: PacketFields):
        self.frame = Frame(fields.frame_time)
        self.ip = IP(fields.src_ip, fields.dst_ip)
        self.udp = UDP(fields.src_port, fields.dst_port)


class PacketCapture:
    def __init__(
        self,
        interface: str,
        tshark_path: Path,
        tshark_version: str,
        capture_filter: str | None = None,
        display_filter: str | None = None,
    ):
        from modules.constants.standard import RE_WIRESHARK_VERSION_PATTERN

        self.interface = interface
        self.tshark_path = tshark_path
        self.tshark_version = tshark_version
        self.capture_filter = capture_filter
        self.display_filter = display_filter

        self._EXPECTED_PACKET_FIELDS = 5

        # Extract Wireshark version
        if not (match := RE_WIRESHARK_VERSION_PATTERN.search(tshark_version)):
            raise ValueError("Could not extract Wireshark version")

        extracted_version = match.group("version")
        if not isinstance(extracted_version, str):
            raise TypeError(f'Expected "str", got "{type(extracted_version).__name__}"')

        self.extracted_tshark_version = extracted_version

        # Build TShark command
        self._tshark_command = [
            str(tshark_path),
            "-l", "-n", "-Q",
            "--log-level", "critical",
            "-B", "1",
            "-i", interface,
            *(["-f", capture_filter] if capture_filter else []),
            *(["-Y", display_filter] if display_filter else []),
            "-T", "fields",
            "-E", "separator=|",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
        ]
        self._tshark_process: subprocess.Popen[str] | None = None

    def apply_on_packets(self, callback: Callable[[Packet], None]):
        for packet in self._capture_packets():
            callback(packet)

    def _capture_packets(self):
        def process_tshark_stdout(line: str):
            fields = line.split("|", self._EXPECTED_PACKET_FIELDS - 1)
            if len(fields) != self._EXPECTED_PACKET_FIELDS:
                raise ValueError(
                    "Unexpected number of fields in TShark output. "
                    f'Expected "{self._EXPECTED_PACKET_FIELDS}", got "{len(fields)}": "{fields}"',
                )

            fields = [field.strip() for field in fields]  # Strip whitespace from each field

            # Ensure the first three fields are not empty
            if any(not field for field in fields[:3]):
                raise ValueError(
                    "One of the required first three fields is empty. Fields: " + str(fields),
                )

            # TODO(BUZZARDGTA): In future development, it would be ideal to retain these packets instead of discarding them.
            # Displaying "None" in the Port field should be supported at some point.
            # Allow the last two fields (source and destination ports) to be empty.
            if "" in {fields[-2], fields[-1]}:
                print(f"Source or destination port is missing. Packet ignored: [{line}]")
                return None  # Skip processing if either of the last two fields is empty

            if not (fields[-2].isdigit() and fields[-1].isdigit()):
                raise ValueError("Source and destination ports must be digits.")

            return PacketFields(*fields)

        with subprocess.Popen(
            self._tshark_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as process:
            self._tshark_process = process

            if process.stdout:
                # Iterate over stdout line by line as it is being produced
                for line in process.stdout:
                    packet_fields = process_tshark_stdout(line.rstrip())
                    if packet_fields is None:
                        continue

                    yield Packet(packet_fields)

            # After stdout is done, check if there were any errors in stderr
            if process.stderr:
                stderr_output = process.stderr.read()
                if process.returncode != 0:
                    raise TSharkCrashExceptionError(f"TShark exited with error code {process.returncode}:\n{stderr_output.strip()}")


def converts_tshark_packet_timestamp_to_datetime_object(packet_frame_time_epoch: str):
    return datetime.fromtimestamp(timestamp=float(packet_frame_time_epoch), tz=LOCAL_TZ)
