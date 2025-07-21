"""Module for defining constants that include only imports from standard Python libraries."""
import os
import re
import textwrap
from datetime import datetime
from pathlib import Path

from .external import LOCAL_TZ

# Get the SystemRoot environment variable dynamically
system_root = Path(os.environ.get("SYSTEMROOT", "C:/Windows"))
system32 = system_root / "System32"
CMD_EXE = system32 / "cmd.exe"
SC_EXE = system32 / "sc.exe"
SHUTDOWN_EXE = system32 / "shutdown.exe"

SETTINGS_PATH = Path("Settings.ini")
USERIP_DATABASES_PATH = Path("UserIP Databases")
USERIP_LOGGING_PATH = Path("UserIP_Logging.log")
GEOLITE2_DATABASES_FOLDER_PATH = Path("GeoLite2 Databases")
SESSIONS_LOGGING_PATH = Path("Sessions Logging") / datetime.now(tz=LOCAL_TZ).strftime("%Y/%m/%d") / f"{datetime.now(tz=LOCAL_TZ).strftime('%Y-%m-%d_%H-%M-%S')}.log"

# Compiled regex for matching the optional time component in the version string
RE_VERSION_TIME = re.compile(r" \((\d{2}:\d{2})\)$")
RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)")
RE_USERIP_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)")
RE_MODMENU_LOGS_USER_PATTERN = re.compile(r"^user:(?P<username>[\w._-]{1,16}), scid:\d{1,9}, ip:(?P<ip>[\d.]+), timestamp:\d{10}$")
RE_WIRESHARK_VERSION_PATTERN = re.compile(r"\b(?P<version>\d+\.\d+\.\d+)\b")
RE_BYTES_PATTERN = re.compile(r"(?P<NUM_OF_BYTES>[\d]+) bytes? from (?P<IP>\d+\.\d+\.\d+\.\d+): icmp_seq=(?P<ICMP_SEQ>\d+) ttl=(?P<TTL>\d+) time=(?P<TIME_MS>[\d\.]+) ms")
# NOTE: I don't need this one so far, but who knows maybe later.
# RE_HOST_UNREACHABLE_PATTERN = re.compile(r"From (?P<IP>\d+\.\d+\.\d+\.\d+) icmp_seq=(?P<ICMP_SEQ>\d+) Destination Host Unreachable")
RE_PACKET_STATS_PATTERN = re.compile(r"(?P<PACKETS_TRANSMITTED>\d+) packets? transmitted, (?P<PACKETS_RECEIVED>\d+) received(?:, \+(?P<ERRORS>\d+) errors?)?, (?P<PACKET_LOSS_PERCENTAGE>\d+(?:\.\d+)?)% packet loss, time (?P<TIME>\d+)ms")
RE_RTT_STATS_PATTERN = re.compile(r"rtt min/avg/max/mdev = (?P<RTT_MIN>[\d\.]+)/(?P<RTT_AVG>[\d\.]+)/(?P<RTT_MAX>[\d\.]+)/(?P<RTT_MDEV>[\d\.]+) ms")

# TODO(BUZZARDGTA): Implement a better way to retrieve the default background color for table cells.
# Currently hardcoded to Gray.B10, which should be the same color for everyone.
CUSTOM_CONTEXT_MENU_STYLESHEET = textwrap.dedent("""
    QMenu {
        background-color: #1e1e1e;     /* Dark background */
        border: 1px solid #2d2d2d;     /* Subtle border */
        border-radius: 8px;            /* Rounded corners */
        padding: 4px;                  /* Space inside the menu */
    }

    QMenu::item {
        color: #d4d4d4;                /* Light gray text color */
        padding: 6px 20px;             /* Padding for each item */
        background-color: transparent; /* Default background */
    }

    QMenu::item:selected {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 #4a90e2,           /* Soft blue gradient start */
            stop: 1 #3c5a9a            /* Muted navy blue gradient end */
        );
        color: #ffffff;                /* White text for better contrast */
        border: 1px solid #5a5a5a;     /* Subtle border for selection */
        border-radius: 6px;            /* Rounded corners for selection */
        margin: 2px;                   /* Spacing around the item */
    }

    QMenu::item:disabled {
        color: #7F7F91;                /* Greyed-out text for disabled items */
        background-color: transparent; /* No background for disabled items */
    }

    QMenu::item:disabled:hover,
    QMenu::item:disabled:selected {
        background-color: transparent; /* Prevent hover or selection color */
        color: #7F7F91;                /* Ensure text remains greyed-out */
        border: none;                  /* Remove any border effect */
    }

    QMenu::item:pressed {
        background-color: #36547c;     /* Slightly darker blue when pressed */
        color: #e0e0e0;                /* Slightly muted text color */
    }

    QMenu::separator {
        height: 1px;
        background: #2d2d2d;           /* Separator color */
        margin: 4px 0;
    }
""".removeprefix("\n").removesuffix("\n"))
