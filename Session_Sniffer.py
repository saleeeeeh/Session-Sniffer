# ------------------------------------------------------
# 🐍 Standard Python Libraries (Included by Default) 🐍
# ------------------------------------------------------
import os
import sys
import ast
import json
import time
import enum
import errno
import signal
import shutil
import logging
import hashlib
import textwrap
import tempfile
import winsound
import threading
import subprocess
import webbrowser
from pathlib import Path
from operator import attrgetter
from datetime import datetime, timedelta
from traceback import TracebackException
from types import FrameType, TracebackType
from typing import Optional, Literal, Union, Type, NamedTuple, Any
from ipaddress import IPv4Address, AddressValueError
from dataclasses import dataclass, field

# --------------------------------------------
# 📦 External/Third-party Python Libraries 📦
# --------------------------------------------
import wmi
import psutil
import colorama
import requests
import qdarkstyle
import geoip2.errors
import geoip2.database
from wmi import _wmi_namespace, _wmi_object
from prettytable import PrettyTable, TableStyle
from colorama import Fore
from rich.text import Text
from rich.console import Console
from rich.traceback import Traceback
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QAbstractTableModel, QItemSelectionModel, QItemSelection, QPoint, QModelIndex
from PyQt6.QtWidgets import QApplication, QTableView, QVBoxLayout, QWidget, QSizePolicy, QLabel, QFrame, QHeaderView, QMenu, QInputDialog, QMainWindow, QMessageBox
from PyQt6.QtGui import QBrush, QColor, QFont, QCloseEvent, QKeyEvent, QClipboard, QMouseEvent, QAction

# -----------------------------------------------------
# 📚 Local Python Libraries (Included with Project) 📚
# -----------------------------------------------------
from Modules.constants.standalone import TITLE, VERSION, TSHARK_RECOMMENDED_FULL_VERSION, TSHARK_RECOMMENDED_VERSION_NUMBER
from Modules.constants.standard import SETTINGS_PATH
from Modules.utils import Version
from Modules.msgbox import MsgBox
from Modules.networking.oui_lookup import MacLookup
from Modules.networking.unsafe_https import s
from Modules.capture.tshark_capture import PacketCapture, Packet, TSharkCrashException
from Modules.capture.utils.tshark_validator import TSharkNotFoundException, TSharkVersionNotFoundException, InvalidTSharkVersionException, validate_tshark_path
from Modules.capture.utils.npcap_checker import is_npcap_installed


if sys.version_info.major <= 3 and sys.version_info.minor < 12:
    print("To use this script, your Python version must be 3.12 or higher.")
    sys.exit(0)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M",
    handlers=[
        logging.FileHandler("error.log")
        # rich.traceback does it nicer ---> logging.StreamHandler(sys.stdout)
    ]
)
logging.captureWarnings(True)


class ExceptionInfo(NamedTuple):
    exc_type: Type[BaseException]
    exc_value: BaseException
    exc_traceback: Optional[TracebackType]

def terminate_script(
        terminate_method: Literal["EXIT", "SIGINT", "THREAD_RAISED"],
        msgbox_crash_text: Optional[str] = None,
        stdout_crash_text: Optional[str] = None,
        exception_info: Optional[ExceptionInfo] = None,
        terminate_gracefully = True,
        force_terminate_errorlevel: Union[int, Literal[False]] = False
    ):

    def should_terminate_gracefully():
        if terminate_gracefully is False:
            return False

        for thread_name in ("capture_core__thread", "rendering_core__thread", "hostname_core__thread", "iplookup_core__thread", "pinger_core__thread"):
            if thread_name in globals():
                thread = globals()[thread_name]
                if isinstance(thread, threading.Thread):
                    if thread.is_alive():
                        return False

        # TODO: Gracefully exit the script even when the `cature` module is running.
        if "capture" in globals():
            if capture is not None and isinstance(capture, PacketCapture):
                return False

        return True

    ScriptControl.set_crashed(None if stdout_crash_text is None else f"\n\n{stdout_crash_text}\n")

    if exception_info:
        logging.error("Uncaught exception", exc_info=(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback))

        console = Console()

        traceback_message = Traceback.from_exception(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback)
        console.print(traceback_message)

        error_message = Text.from_markup(
            (
                "\n\n\nAn unexpected (uncaught) error occurred. [bold]Please kindly report it to:[/bold]\n"
                "[link=https://github.com/BUZZARDGTA/Session-Sniffer/issues]"
                "https://github.com/BUZZARDGTA/Session-Sniffer/issues[/link].\n\n"
                "DEBUG:\n"
                f"VERSION={globals().get('VERSION', 'Unknown Version')}"  # Define a default value for VERSION if it's not defined
            ),
            style="white"
        )
        console.print(error_message)

    if stdout_crash_text is not None:
        print(ScriptControl.get_message())

    if msgbox_crash_text is not None:
        msgbox_title = TITLE
        msgbox_message = msgbox_crash_text
        msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Critical | MsgBox.Style.SystemModal | MsgBox.Style.MsgBoxSetForeground

        MsgBox.show(msgbox_title, msgbox_message, msgbox_style)
        time.sleep(1)

    # If the termination method is "EXIT", do not sleep unless crash messages are present
    need_sleep = True
    if terminate_method == "EXIT" and msgbox_crash_text is None and stdout_crash_text is None:
        need_sleep = False
    if need_sleep:
        time.sleep(3)

    if should_terminate_gracefully():
        if force_terminate_errorlevel is False:
            errorlevel = 1 if terminate_method == "THREAD_RAISED" else 0
        else:
            errorlevel = force_terminate_errorlevel
        sys.exit(errorlevel)

    terminate_process_tree()

def handle_exception(exc_type: Type[BaseException], exc_value: BaseException, exc_traceback: Optional[TracebackException]):
    """Handles exceptions for the main script. (not threads)"""
    if issubclass(exc_type, KeyboardInterrupt):
        return

    exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
    terminate_script("EXIT", "An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\nhttps://github.com/BUZZARDGTA/Session-Sniffer/issues", exception_info = exception_info)

def signal_handler(sig: int, frame: FrameType):
    if sig == 2: # means CTRL+C pressed
        if not ScriptControl.has_crashed(): # Block CTRL+C if script is already crashing under control
            print(f"\n{Fore.YELLOW}Ctrl+C pressed. Exiting script ...{Fore.RESET}")
            terminate_script("SIGINT")

sys.excepthook = handle_exception
signal.signal(signal.SIGINT, signal_handler)


class InvalidBooleanValueError(Exception):
    pass

class InvalidNoneTypeValueError(Exception):
    pass

class InvalidFileError(Exception):
    def __init__(self, path: str):
        super().__init__(f'The path does not point to a regular file: "{path}"')

class PacketCaptureOverflow(Exception):
    pass

class ScriptControl:
    _lock = threading.Lock()
    _crashed = False
    _message = None

    @classmethod
    def set_crashed(cls, message: Optional[str] = None):
        with cls._lock:
            cls._crashed = True
            cls._message = message

    @classmethod
    def reset_crashed(cls):
        with cls._lock:
            cls._crashed = False
            cls._message = None

    @classmethod
    def has_crashed(cls):
        with cls._lock:
            return cls._crashed

    @classmethod
    def get_message(cls):
        with cls._lock:
            return cls._message

class Updater:
    def __init__(self, current_version: Version):
        self.current_version = current_version

    def check_for_update(self, latest_version: Version):
        # Check if the latest version is newer than the current version
        if (latest_version.major, latest_version.minor, latest_version.patch) > (self.current_version.major, self.current_version.minor, self.current_version.patch):
            return True
        elif (latest_version.major, latest_version.minor, latest_version.patch) == (self.current_version.major, self.current_version.minor, self.current_version.patch):
            # Compare date and time if versioning is equal
            if latest_version.date_time > self.current_version.date_time:
                return True
        return False

class Threads_ExceptionHandler:
    """In Python, threads cannot be raised within the main source code. When raised, they operate independently,
    and the main process continues execution without halting for the thread's completion. To overcome this limitation,
    this class is designed to enhance thread management and provide additional functionality.

    Attributes:
        raising_function (str): The name of the function where the exception was raised.
        raising_exc_type (type): The type of the exception raised.
        raising_exc_value (Exception): The value of the exception raised.
        raising_exc_traceback (TracebackType): The traceback information of the exception raised.
    """
    raising_function = None
    raising_exc_type = None
    raising_exc_value = None
    raising_exc_traceback = None

    def __init__(self):
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type: type, exc_value: Exception, exc_traceback: TracebackType):
        """
        Exit method called upon exiting the 'with' block.

        Args:
            exc_type: The type of the exception raised.
            exc_value: The value of the exception raised.
            exc_traceback: The traceback information of the exception raised.

        Returns:
            bool: True to suppress the exception from propagating further.
        """
        if exc_type:
            Threads_ExceptionHandler.raising_exc_type = exc_type
            Threads_ExceptionHandler.raising_exc_value = exc_value
            Threads_ExceptionHandler.raising_exc_traceback = exc_traceback

            tb = exc_traceback
            while tb.tb_next:
                tb = tb.tb_next
            # Set the failed function name
            Threads_ExceptionHandler.raising_function = tb.tb_frame.f_code.co_name

            exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
            terminate_script("THREAD_RAISED", "An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\nhttps://github.com/BUZZARDGTA/Session-Sniffer/issues", exception_info = exception_info)

            return True  # Prevent exceptions from propagating

@dataclass
class DefaultSettings:
    """Class containing default setting values."""
    CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT = True
    CAPTURE_INTERFACE_NAME = None
    CAPTURE_IP_ADDRESS = None
    CAPTURE_MAC_ADDRESS = None
    CAPTURE_ARP = True
    CAPTURE_BLOCK_THIRD_PARTY_SERVERS = True
    CAPTURE_PROGRAM_PRESET = None
    CAPTURE_VPN_MODE = False
    CAPTURE_OVERFLOW_TIMER = 3.0
    CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER = None
    CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER = None
    GUI_SESSIONS_LOGGING = True
    GUI_RESET_PORTS_ON_REJOINS = True
    GUI_FIELDS_TO_HIDE = ["PPM", "Avg PPM", "Intermediate Ports", "First Port", "Continent", "R. Code", "City", "District", "ZIP Code", "Lat", "Lon", "Time Zone", "Offset", "Currency", "Organization", "ISP", "AS", "ASN"]
    GUI_DATE_FIELDS_SHOW_DATE = False
    GUI_DATE_FIELDS_SHOW_TIME = False
    GUI_DATE_FIELDS_SHOW_ELAPSED = True
    GUI_FIELD_SHOW_COUNTRY_CODE = True
    GUI_FIELD_SHOW_CONTINENT_CODE = True
    GUI_FIELD_CONNECTED_PLAYERS_SORTED_BY = "Last Rejoin"
    GUI_FIELD_DISCONNECTED_PLAYERS_SORTED_BY = "Last Seen"
    GUI_DISCONNECTED_PLAYERS_TIMER = 10.0
    DISCORD_PRESENCE = True
    UPDATER_CHANNEL = "Stable"

class Settings(DefaultSettings):
    gui_fields_mapping = {
        "Usernames": "userip.usernames",
        "First Seen": "datetime.first_seen",
        "Last Rejoin": "datetime.last_rejoin",
        "Last Seen": "datetime.last_seen",
        "Rejoins": "rejoins",
        "T. Packets": "total_packets",
        "Packets": "packets",
        "PPS": "pps.rate",
        #"Avg PPS": "pps.get_average()",
        "PPM": "ppm.rate",
        #"Avg PPM": "ppm.get_average()",
        "IP Address": "ip",
        "Hostname": "hostname",
        "Last Port": "ports.last",
        "Intermediate Ports": "ports.intermediate",
        "First Port": "ports.first",
        "Continent": "iplookup.ipapi.continent",
        "Country": "iplookup.geolite2.country",
        "Region": "iplookup.ipapi.region",
        "R. Code": "iplookup.ipapi.region_code",
        "City": "iplookup.geolite2.city",
        "District": "iplookup.ipapi.district",
        "ZIP Code": "iplookup.ipapi.zip_code",
        "Lat": "iplookup.ipapi.lat",
        "Lon": "iplookup.ipapi.lon",
        "Time Zone": "iplookup.ipapi.time_zone",
        "Offset": "iplookup.ipapi.offset",
        "Currency": "iplookup.ipapi.currency",
        "Organization": "iplookup.ipapi.org",
        "ISP": "iplookup.ipapi.isp",
        "ASN / ISP": "iplookup.geolite2.asn",
        "AS": "iplookup.ipapi._as",
        "ASN": "iplookup.ipapi.as_name",
        "Mobile": "iplookup.ipapi.mobile",
        "VPN": "iplookup.ipapi.proxy",
        "Hosting": "iplookup.ipapi.hosting",
        "Pinging": "ping.is_pinging"
    }
    gui_forced_fields           = ["Usernames", "First Seen", "Last Rejoin", "Last Seen", "Rejoins", "T. Packets", "Packets", "IP Address"]
    gui_hideable_fields         = ["PPS", "Avg PPS", "PPM", "Avg PPM", "Hostname", "Last Port", "Intermediate Ports", "First Port", "Continent", "Country", "Region", "R. Code", "City", "District", "ZIP Code", "Lat", "Lon", "Time Zone", "Offset", "Currency", "Organization", "ISP", "ASN / ISP", "AS", "ASN", "Mobile", "VPN", "Hosting", "Pinging"]
    gui_all_connected_fields    = ["Usernames", "First Seen", "Last Rejoin",              "Rejoins", "T. Packets", "Packets", "PPS", "Avg PPS", "PPM", "Avg PPM", "IP Address", "Hostname", "Last Port", "Intermediate Ports", "First Port", "Continent", "Country", "Region", "R. Code", "City", "District", "ZIP Code", "Lat", "Lon", "Time Zone", "Offset", "Currency", "Organization", "ISP", "ASN / ISP", "AS", "ASN", "Mobile", "VPN", "Hosting", "Pinging"]
    gui_all_disconnected_fields = ["Usernames", "First Seen", "Last Rejoin", "Last Seen", "Rejoins", "T. Packets", "Packets",                                     "IP Address", "Hostname", "Last Port", "Intermediate Ports", "First Port", "Continent", "Country", "Region", "R. Code", "City", "District", "ZIP Code", "Lat", "Lon", "Time Zone", "Offset", "Currency", "Organization", "ISP", "ASN / ISP", "AS", "ASN", "Mobile", "VPN", "Hosting", "Pinging"]

    @classmethod
    def iterate_over_settings(cls):
        _allowed_settings_types = (type(None), Path, bool, list, str, float, int)

        for attr_name, attr_value in vars(DefaultSettings).items():
            if (
                callable(attr_value)
                or attr_name.startswith("_")
                or attr_name in ("gui_fields_mapping", "gui_forced_fields", "gui_hideable_fields", "gui_all_connected_fields", "gui_all_disconnected_fields")
                or not attr_name.isupper()
                or not isinstance(attr_value, _allowed_settings_types)
            ):
                continue

            # Get the value from Settings if it exists, otherwise from DefaultSettings
            current_value = getattr(cls, attr_name, attr_value)
            yield attr_name, current_value

    @classmethod
    def get_settings_length(cls):
        return sum(1 for _ in cls.iterate_over_settings())

    @classmethod
    def has_setting(cls, setting_name):
        return hasattr(cls, setting_name)

    @staticmethod
    def reconstruct_settings():
        print("\nCorrect reconstruction of \"Settings.ini\" ...")
        text = textwrap.dedent(f"""
            ;;-----------------------------------------------------------------------------
            ;; {TITLE} Configuration Settings
            ;;-----------------------------------------------------------------------------
            ;; Lines starting with \";\" or \"#\" symbols are commented lines.
            ;;
            ;; For detailed explanations of each setting, please refer to the following documentation:
            ;; https://github.com/BUZZARDGTA/Session-Sniffer/?tab=readme-ov-file#editing-settings
            ;;-----------------------------------------------------------------------------
        """.removeprefix("\n"))
        for setting_name, setting_value in Settings.iterate_over_settings():
            text += f"{setting_name}={setting_value}\n"
        SETTINGS_PATH.write_text(text, encoding="utf-8")

    @staticmethod
    def load_from_settings_file(settings_path: Path):
        matched_settings_count = 0

        try:
            settings, need_rewrite_settings = parse_settings_ini_file(settings_path, values_handling="first")
            settings: dict[str, str]
        except FileNotFoundError:
            need_rewrite_settings = True
        else:
            for setting_name, setting_value in settings.items():
                if not Settings.has_setting(setting_name):
                    need_rewrite_settings = True
                    continue

                matched_settings_count += 1
                need_rewrite_current_setting = False

                if setting_name == "CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT":
                    try:
                        Settings.CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_INTERFACE_NAME":
                    try:
                        Settings.CAPTURE_INTERFACE_NAME, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.CAPTURE_INTERFACE_NAME = setting_value
                elif setting_name == "CAPTURE_IP_ADDRESS":
                    try:
                        Settings.CAPTURE_IP_ADDRESS, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        if is_ipv4_address(setting_value):
                            Settings.CAPTURE_IP_ADDRESS = setting_value
                        else:
                            need_rewrite_settings = True
                elif setting_name == "CAPTURE_MAC_ADDRESS":
                    try:
                        Settings.CAPTURE_MAC_ADDRESS, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        if is_mac_address(setting_value):
                            formatted_mac_address = format_mac_address(setting_value)
                            if not formatted_mac_address == setting_value:
                                need_rewrite_settings = True
                            Settings.CAPTURE_MAC_ADDRESS = formatted_mac_address
                        else:
                            need_rewrite_settings = True
                elif setting_name == "CAPTURE_ARP":
                    try:
                        Settings.CAPTURE_ARP, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_BLOCK_THIRD_PARTY_SERVERS":
                    try:
                        Settings.CAPTURE_BLOCK_THIRD_PARTY_SERVERS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_PROGRAM_PRESET":
                    try:
                        Settings.CAPTURE_PROGRAM_PRESET, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, ["GTA5", "Minecraft"])
                        if case_insensitive_match:
                            Settings.CAPTURE_PROGRAM_PRESET = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        else:
                            need_rewrite_settings = True
                elif setting_name == "CAPTURE_VPN_MODE":
                    try:
                        Settings.CAPTURE_VPN_MODE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_OVERFLOW_TIMER":
                    try:
                        CAPTURE_OVERFLOW_TIMER = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if CAPTURE_OVERFLOW_TIMER >= 1:
                            Settings.CAPTURE_OVERFLOW_TIMER = CAPTURE_OVERFLOW_TIMER
                        else:
                            need_rewrite_settings = True
                elif setting_name == "CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER":
                    try:
                        Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        if updated_setting_value := setting_value.strip().strip("\"'").strip("()"):
                            Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER = f"({updated_setting_value})"
                        else:
                            need_rewrite_settings = True
                elif setting_name == "CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER":
                    try:
                        Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        if updated_setting_value := setting_value.strip().strip("\"'").strip("()"):
                            Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER = f"({updated_setting_value})"
                        else:
                            need_rewrite_settings = True
                elif setting_name == "GUI_SESSIONS_LOGGING":
                    try:
                        Settings.GUI_SESSIONS_LOGGING, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "GUI_RESET_PORTS_ON_REJOINS":
                    try:
                        Settings.GUI_RESET_PORTS_ON_REJOINS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "GUI_FIELDS_TO_HIDE":
                    try:
                        gui_fields_to_hide: list[str] = ast.literal_eval(setting_value)
                    except (ValueError, SyntaxError):
                        need_rewrite_settings = True
                    else:
                        if isinstance(gui_fields_to_hide, list) and all(isinstance(item, str) for item in gui_fields_to_hide):
                            filtered_gui_fields_to_hide: list[str] = []

                            for value in gui_fields_to_hide:
                                case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, Settings.gui_hideable_fields)
                                if case_insensitive_match:
                                    filtered_gui_fields_to_hide.append(normalized_match)
                                    if not case_sensitive_match:
                                        need_rewrite_current_setting = True
                                else:
                                    need_rewrite_settings = True

                            Settings.GUI_FIELDS_TO_HIDE = filtered_gui_fields_to_hide
                        else:
                            need_rewrite_settings = True
                elif setting_name == "GUI_DATE_FIELDS_SHOW_DATE":
                    try:
                        Settings.GUI_DATE_FIELDS_SHOW_DATE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "GUI_DATE_FIELDS_SHOW_TIME":
                    try:
                        Settings.GUI_DATE_FIELDS_SHOW_TIME, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "GUI_DATE_FIELDS_SHOW_ELAPSED":
                    try:
                        Settings.GUI_DATE_FIELDS_SHOW_ELAPSED, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "GUI_FIELD_SHOW_CONTINENT_CODE":
                    try:
                        Settings.GUI_FIELD_SHOW_CONTINENT_CODE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "GUI_FIELD_SHOW_COUNTRY_CODE":
                    try:
                        Settings.GUI_FIELD_SHOW_COUNTRY_CODE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "GUI_FIELD_CONNECTED_PLAYERS_SORTED_BY":
                    case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, Settings.gui_all_connected_fields)
                    if case_insensitive_match:
                        Settings.GUI_FIELD_CONNECTED_PLAYERS_SORTED_BY = normalized_match
                        if not case_sensitive_match:
                            need_rewrite_current_setting = True
                    else:
                        need_rewrite_settings = True
                elif setting_name == "GUI_FIELD_DISCONNECTED_PLAYERS_SORTED_BY":
                    case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, Settings.gui_all_disconnected_fields)
                    if case_insensitive_match:
                        Settings.GUI_FIELD_DISCONNECTED_PLAYERS_SORTED_BY = normalized_match
                        if not case_sensitive_match:
                            need_rewrite_current_setting = True
                    else:
                        need_rewrite_settings = True
                elif setting_name == "GUI_DISCONNECTED_PLAYERS_TIMER":
                    try:
                        player_disconnected_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if player_disconnected_timer >= 3.0:
                            Settings.GUI_DISCONNECTED_PLAYERS_TIMER = player_disconnected_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == "DISCORD_PRESENCE":
                    try:
                        Settings.DISCORD_PRESENCE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "UPDATER_CHANNEL":
                    try:
                        Settings.UPDATER_CHANNEL, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, ["Stable", "Alpha"])
                        if case_insensitive_match:
                            Settings.UPDATER_CHANNEL = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        else:
                            need_rewrite_settings = True

                if need_rewrite_current_setting:
                    need_rewrite_settings = True

            if not matched_settings_count == Settings.get_settings_length():
                need_rewrite_settings = True

        if need_rewrite_settings:
            Settings.reconstruct_settings()

        for field_name in Settings.GUI_FIELDS_TO_HIDE:
            for sort_field_name, sort_field_value, default_sort_value in (
                ("GUI_FIELD_CONNECTED_PLAYERS_SORTED_BY", Settings.GUI_FIELD_CONNECTED_PLAYERS_SORTED_BY, DefaultSettings.GUI_FIELD_CONNECTED_PLAYERS_SORTED_BY),
                ("GUI_FIELD_DISCONNECTED_PLAYERS_SORTED_BY", Settings.GUI_FIELD_DISCONNECTED_PLAYERS_SORTED_BY, DefaultSettings.GUI_FIELD_DISCONNECTED_PLAYERS_SORTED_BY)
            ):
                if field_name in sort_field_value:
                    need_rewrite_settings = True

                    msgbox_title = TITLE
                    msgbox_message = textwrap.dedent(f"""
                        ERROR in your custom \"Settings.ini\" file:

                        You cannot sort players in the output from a hidden gui field (<GUI_FIELDS_TO_HIDE>).

                        Would you like to replace:
                        {sort_field_name}={sort_field_value}
                        with its default value:
                        {sort_field_name}={default_sort_value}
                    """.removeprefix("\n").removesuffix("\n"))
                    msgbox_style = MsgBox.Style.YesNo | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
                    errorlevel = MsgBox.show(msgbox_title, msgbox_message, msgbox_style)

                    if errorlevel != MsgBox.ReturnValues.IDYES:
                        terminate_script("EXIT")

                    setattr(Settings, sort_field_name, getattr(DefaultSettings, sort_field_name)) # Replace the incorrect field with its default value
                    Settings.reconstruct_settings()

        if Settings.GUI_DATE_FIELDS_SHOW_DATE is False and Settings.GUI_DATE_FIELDS_SHOW_TIME is False and Settings.GUI_DATE_FIELDS_SHOW_ELAPSED is False:
            msgbox_title = TITLE
            msgbox_message = textwrap.dedent(f"""
                ERROR in your custom \"Settings.ini\" file:

                At least one of these settings must be set to \"True\" value:
                <GUI_DATE_FIELDS_SHOW_DATE>
                <GUI_DATE_FIELDS_SHOW_TIME>
                <GUI_DATE_FIELDS_SHOW_ELAPSED>

                Would you like to apply their default values and continue?
            """.removeprefix("\n").removesuffix("\n"))
            msgbox_style = MsgBox.Style.YesNo | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
            errorlevel = MsgBox.show(msgbox_title, msgbox_message, msgbox_style)

            if errorlevel != MsgBox.ReturnValues.IDYES:
                terminate_script("EXIT")

            for setting_name in ("GUI_DATE_FIELDS_SHOW_DATE", "GUI_DATE_FIELDS_SHOW_TIME", "GUI_DATE_FIELDS_SHOW_ELAPSED"):
                setattr(Settings, setting_name, getattr(DefaultSettings, setting_name))

            Settings.reconstruct_settings()

@dataclass
class Adapter_Properties:
    Name          : Union[Literal["N/A"], str] = "N/A"
    InterfaceIndex: Union[Literal["N/A"], int] = "N/A"
    Manufacturer  : Union[Literal["N/A"], str] = "N/A"

class Interface:
    all_interfaces: list["Interface"] = []

    def __init__(self, interface_name: str):
        self.interface_name = interface_name

        self.ip_addresses     : list[str]                  = []
        self.mac_address      : Union[Literal["N/A"], str] = "N/A"
        self.organization_name: Union[Literal["N/A"], str] = "N/A"
        self.packets_sent     : Union[Literal["N/A"], int] = "N/A"
        self.packets_recv     : Union[Literal["N/A"], int] = "N/A"
        self.arp_infos        : list[dict[str, str]]       = []

        self.adapter_properties = Adapter_Properties()

        Interface.all_interfaces.append(self)

    def add_arp_infos(self, arp_infos: list[dict[str, str]]):
        """
        Add ARP informations for the given interface.
        """
        for arp_info in arp_infos:
            if arp_info not in self.arp_infos:
                self.arp_infos.append(arp_info)

    def get_arp_infos(self):
        """
        Get ARP informations for the given interface.
        """
        return self.arp_infos

    @classmethod
    def get_interface_by_name(cls, interface_name: str):
        for interface in cls.iterate_safely():
            if interface.interface_name == interface_name:
                return interface
        return None

    @classmethod
    def get_interface_by_id(cls, interface_index: int):
        for interface in cls.iterate_safely():
            if interface.adapter_properties.InterfaceIndex == interface_index:
                return interface
        return None

    @classmethod
    def delete_interface(cls, interface: "Interface"):
        """
        Delete an interface.
        """
        cls.all_interfaces.remove(interface)

    @classmethod
    def iterate_safely(cls):
        """
        Safely iterate over all_interfaces, allowing modifications during iteration.
        """
        for interface in cls.all_interfaces[:]:  # Iterate over a copy of the list
            yield interface

class ThirdPartyServers(enum.Enum):
    PC_DISCORD = ("66.22.196.0/22", "66.22.200.0/21", "66.22.208.0/20", "66.22.224.0/20", "66.22.240.0/21", "66.22.248.0/24")
    PC_VALVE = ("103.10.124.0/23", "103.28.54.0/23", "146.66.152.0/21", "155.133.224.0/19", "162.254.192.0/21", "185.25.180.0/22", "205.196.6.0/24") # Valve = Steam
    PC_GOOGLE = ("34.0.0.0/9", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/11", "35.224.0.0/12", "35.240.0.0/13")
    PC_MULTICAST = ("224.0.0.0/4",)
    PC_UK_MINISTRY_OF_DEFENCE = ("25.0.0.0/8",)
    PC_SERVERS_COM = ("173.237.26.0/24",)
    PC_OTHERS = ("113.117.15.193/32",)
    GTAV_PC_AND_PS3_TAKETWO = ("104.255.104.0/23", "104.255.106.0/24", "185.56.64.0/22", "192.81.241.0/24", "192.81.244.0/23")
    GTAV_PC_MICROSOFT = ("52.139.128.0/18",)
    GTAV_PC_DOD_NETWORK_INFORMATION_CENTER = ("26.0.0.0/8",)
    GTAV_PC_BATTLEYE = ("51.89.97.102/32", "51.89.99.255/32")
    GTAV_XBOXONE_MICROSOFT = ("52.159.128.0/17", "52.160.0.0/16", "40.74.0.0/18")
    PS5_AMAZON = ("52.40.62.0/25", "44.192.0.0/10")
    MINECRAFTBEDROCKEDITION_PC_AND_PS3_MICROSOFT = ("20.202.0.0/24", "20.224.0.0/16", "168.61.142.128/25", "168.61.143.0/24", "168.61.144.0/20", "168.61.160.0/19")

    @classmethod
    def get_all_ip_ranges(cls):
        """Returns a flat list of all IP ranges from the Enum."""
        return [ip_range for server in cls for ip_range in server.value]

@dataclass
class Player_ReverseDNS:
    is_initialized = False

    hostname: Union[Literal["..."], str] = "..."

class Player_PPS:
    def __init__(self):
        self._initialize()

    def _initialize(self):
        self.is_first_calculation = True
        self.last_update_time = time.monotonic()
        self.last_pps_values: list[int] = []  # Stores last 3 PPS values
        self.counter = 0
        self.rate = 0
        self.avg_rate = 0

    def reset(self):
        self._initialize()

    def update_average(self, player_pps_rate: int):
        """ Safely updates the last PPS values list, keeping only the latest 3 values. """
        if len(self.last_pps_values) >= 3:
            self.last_pps_values.pop(0)  # Keep only the last 3 values
        self.last_pps_values.append(player_pps_rate)

    def get_average(self):
        """ Returns the average of the last 3 PPS values (or fewer if not enough data). """
        return int(sum(self.last_pps_values) / len(self.last_pps_values)) if self.last_pps_values else 0

class Player_PPM:
    def __init__(self):
        self._initialize()

    def _initialize(self):
        self.is_first_calculation = True
        self.last_ppm_values: list[int] = []  # Stores last 3 PPM values
        self.last_update_time = time.monotonic()
        self.counter = 0
        self.rate = 0
        self.avg_rate = 0

    def reset(self):
        self._initialize()

    def update_average(self, player_ppm_counter: int):
        """ Safely updates the last PPM values list, keeping only the latest 3 values. """
        if len(self.last_ppm_values) >= 3:
            self.last_ppm_values.pop(0)  # Keep only the last 3 values
        self.last_ppm_values.append(player_ppm_counter)

    def get_average(self):
        """ Returns the average of the last 3 PPM values (or fewer if not enough data). """
        return round(sum(self.last_ppm_values) / len(self.last_ppm_values)) if self.last_ppm_values else 0

class Player_Ports:
    def __init__(self, port: int):
        self._initialize(port)

    def _initialize(self, port: int):
        self.list = [port]
        self.first = port
        self.intermediate: list[int] = []
        self.last = port

    def reset(self, port: int):
        self._initialize(port)

class Player_DateTime:
    def __init__(self, packet_datetime: datetime):
        self._initialize(packet_datetime)

    def _initialize(self, packet_datetime: datetime):
        self.first_seen = packet_datetime
        self.last_rejoin = packet_datetime
        self.last_seen = packet_datetime
        self.left: Optional[datetime] = None

    def reset(self, packet_datetime: datetime):
        self._initialize(packet_datetime)

@dataclass
class Player_GeoLite2:
    is_initialized = False

    country:      Union[Literal["..."], str] = "..."
    country_code: Union[Literal["..."], str] = "..."
    city:         Union[Literal["..."], str] = "..."
    asn:          Union[Literal["..."], str] = "..."

@dataclass
class Player_IPAPI:
    is_initialized = False

    continent:      Union[Literal["N/A", "..."], str]               = "..."
    continent_code: Union[Literal["N/A", "..."], str]               = "..."
    country:        Union[Literal["N/A", "..."], str]               = "..."
    country_code:   Union[Literal["N/A", "..."], str]               = "..."
    region:         Union[Literal["N/A", "..."], str]               = "..."
    region_code:    Union[Literal["N/A", "..."], str]               = "..."
    city:           Union[Literal["N/A", "..."], str]               = "..."
    district:       Union[Literal["N/A", "..."], str]               = "..."
    zip_code:       Union[Literal["N/A", "..."], str]               = "..."
    lat:            Union[Literal["N/A", "..."], Union[float, int]] = "..."
    lon:            Union[Literal["N/A", "..."], Union[float, int]] = "..."
    time_zone:      Union[Literal["N/A", "..."], str]               = "..."
    offset:         Union[Literal["N/A", "..."], int]               = "..."
    currency:       Union[Literal["N/A", "..."], str]               = "..."
    org:            Union[Literal["N/A", "..."], str]               = "..."
    isp:            Union[Literal["N/A", "..."], str]               = "..."
    _as:            Union[Literal["N/A", "..."], str]               = "..."
    as_name:        Union[Literal["N/A", "..."], str]               = "..."
    mobile:         Union[Literal["N/A", "..."], bool]              = "..."
    proxy:          Union[Literal["N/A", "..."], bool]              = "..."
    hosting:        Union[Literal["N/A", "..."], bool]              = "..."

class Player_IPLookup:
    def __init__(self):
        self.geolite2 = Player_GeoLite2()
        self.ipapi = Player_IPAPI()

@dataclass
class Player_Ping:
    is_initialized = False

    is_pinging:          Union[Literal["..."], bool]            = "..."
    ping_times:          Union[Literal["..."], list[float]]     = "..."
    packets_transmitted: Union[Literal["..."], Optional[int]]   = "..."
    packets_received:    Union[Literal["..."], Optional[int]]   = "..."
    packet_loss:         Union[Literal["..."], Optional[float]] = "..."
    packet_errors:       Union[Literal["..."], Optional[int]]   = "..."
    rtt_min:             Union[Literal["..."], Optional[float]] = "..."
    rtt_avg:             Union[Literal["..."], Optional[float]] = "..."
    rtt_max:             Union[Literal["..."], Optional[float]] = "..."
    rtt_mdev:            Union[Literal["..."], Optional[float]] = "..."

@dataclass
class Player_Detection:
    type: Optional[Literal["Static IP"]] = None
    time: Optional[str] = None
    date_time: Optional[str] = None
    as_processed_userip_task = False

class Player_UserIp:
    def __init__(self):
        self._initialize()

    def _initialize(self):
        self.database_path: Optional[Path] = None
        self.settings: Optional[UserIP_Settings] = None
        self.usernames: list[str] = []
        self.detection = Player_Detection()

    def reset(self):
        self._initialize()

@dataclass
class Player_ModMenus:
    usernames: list[str] = field(default_factory=list)

class Player:
    def __init__(self, ip: str, port: int, packet_datetime: datetime):
        self.is_player_just_registered = True
        self._initialize(ip, port, packet_datetime)

    def _initialize(self, ip: str, port: int, packet_datetime: datetime):
        self.ip = ip
        self.rejoins = 0
        self.packets = 1
        self.total_packets = 1
        self.usernames: list[str] = []

        self.reverse_dns = Player_ReverseDNS()
        self.pps = Player_PPS()
        self.ppm = Player_PPM()
        self.ports = Player_Ports(port)
        self.datetime = Player_DateTime(packet_datetime)
        self.iplookup = Player_IPLookup()
        self.ping = Player_Ping()
        self.userip = Player_UserIp()
        self.mod_menus = Player_ModMenus()

    def reset(self, port: int, packet_datetime: datetime):
        self.packets = 1
        self.pps.reset(packet_datetime)
        self.ppm.reset(packet_datetime)
        self.ports.reset(port)
        self.datetime.reset(packet_datetime)

class PlayersRegistry:
    players_registry: dict[str, Player] = {}

    _sorted_players_cache: list[Player] = []
    _cache_lock = threading.Lock()

    # Constant for the default sort order
    DEFAULT_SORT_ORDER = "datetime.last_rejoin"

    @classmethod
    def add_player(cls, player: Player):
        if player.ip in cls.players_registry:
            raise ValueError(f'Player with IP "{player.ip}" already exists.')
        cls.players_registry[player.ip] = player
        return player

    @classmethod
    def get_player(cls, ip: str):
        return cls.players_registry.get(ip)

    @classmethod
    def iterate_players_from_registry(cls, sort_order: str = DEFAULT_SORT_ORDER, reverse = False):
        # Using list() ensures a static snapshot of the dictionary's values is used, avoiding the 'RuntimeError: dictionary changed size during iteration'.
        for player in sorted(
            list(cls.players_registry.values()),
            key=attrgetter(sort_order),
            reverse=reverse
        ):
            yield player

    @classmethod
    def _update_sorted_cache(cls, sort_order: str = DEFAULT_SORT_ORDER, reverse = False):
        """Refresh the cached sorted player list every second."""
        while not gui_closed__event.is_set():
            with cls._cache_lock:
                cls._sorted_players_cache = sorted(
                    cls.players_registry.values(),
                    key=attrgetter(sort_order),
                    reverse=reverse
                )
            gui_closed__event.wait(1)  # Sleep for 1 second

    @classmethod
    def get_sorted_players(cls, sort_order: str = DEFAULT_SORT_ORDER, reverse = False):
        """Return the cached sorted players list (thread-safe)."""
        with cls._cache_lock:
            if sort_order == cls.DEFAULT_SORT_ORDER:
                # Return the list as is if the default sort order is requested
                return cls._sorted_players_cache.copy()
            else:
                return sorted(cls._sorted_players_cache, key=attrgetter(sort_order), reverse=reverse)

    @classmethod
    def start_cache_updater(cls, sort_order: str = DEFAULT_SORT_ORDER, reverse = False):
        """Start the background thread to update the player cache."""
        thread = threading.Thread(target=cls._update_sorted_cache, args=(sort_order, reverse), daemon=True)
        thread.start()

class SessionHost:
    player: Optional[Player] = None
    search_player = False
    players_pending_for_disconnection: list[Player] = []

    @staticmethod
    def get_host_player(session_connected: list[Player]):
        connected_players: list[Player] = take(2, sorted(session_connected, key=attrgetter("datetime.last_rejoin")))

        potential_session_host_player = None

        if len(connected_players) == 1:
            potential_session_host_player = connected_players[0]
        elif len(connected_players) == 2:
            time_difference = connected_players[1].datetime.last_rejoin - connected_players[0].datetime.last_rejoin
            if time_difference >= timedelta(milliseconds=200):
                potential_session_host_player = connected_players[0]
        else:
            raise ValueError(f"Unexpected number of connected players: {len(connected_players)}")

        if potential_session_host_player and (
            # Skip players remaining to be disconnected from the previous session.
            potential_session_host_player not in SessionHost.players_pending_for_disconnection
            # Ensures that we only check for the newly joined session's players.
            # The lower this value, the riskier it becomes, as it could potentially flag a player who ultimately isn't part of the newly discovered session.
            # In such scenarios, a better approach might involve checking around 25-100 packets.
            # However, increasing this value also increases the risk, as the host may have already disconnected.
            and potential_session_host_player.packets >= 50
        ):
            SessionHost.player = potential_session_host_player
            SessionHost.search_player = False

class UserIP_Settings(NamedTuple):
    """
    Class to represent settings with attributes for each setting key.
    """
    ENABLED: bool
    COLOR: QColor
    LOG: bool
    NOTIFICATIONS: bool
    VOICE_NOTIFICATIONS: Union[str, Literal[False]]
    PROTECTION: Literal["Suspend_Process", "Exit_Process", "Restart_Process", "Shutdown_PC", "Restart_PC", False]
    PROTECTION_PROCESS_PATH: Optional[Path]
    PROTECTION_RESTART_PROCESS_PATH: Optional[Path]
    PROTECTION_SUSPEND_PROCESS_MODE: Union[int, float, Literal["Auto", "Manual"]]

class UserIP(NamedTuple):
    """
    Class representing information associated with a specific IP, including settings and usernames.
    """
    ip: str
    database_path: Path
    settings: UserIP_Settings
    usernames: list[str]

class UserIP_Databases:
    userip_databases: list[tuple[Path, UserIP_Settings, dict[str, list[str]]]] = []
    userip_infos_by_ip: dict[str, UserIP] = {}
    ips_set: set[str] = set()
    notified_settings_corrupted: set[Path] = set()
    notified_ip_invalid: set[str] = set()
    notified_ip_conflicts: set[str] = set()
    update_userip_database_lock = threading.Lock()

    @staticmethod
    def _notify_conflict(initial_userip_entry: UserIP, conflicting_database: Path, conflicting_username: str, conflicting_ip: str):
        from Modules.constants.standard import USERIP_DATABASES_PATH

        msgbox_title = TITLE
        msgbox_message = textwrap.indent(textwrap.dedent(f"""
            ERROR:
                UserIP databases IP conflict

            INFOS:
                The same IP cannot be assigned to multiple
                databases.
                Users assigned to this IP will be ignored until
                the conflict is resolved.

            DEBUG:
                \"{initial_userip_entry.database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")}\":
                {', '.join(initial_userip_entry.usernames)}={initial_userip_entry.ip}

                \"{conflicting_database.relative_to(USERIP_DATABASES_PATH).with_suffix("")}\":
                {conflicting_username}={conflicting_ip}
        """.removeprefix("\n").removesuffix("\n")), "    ")
        msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.SystemModal | MsgBox.Style.MsgBoxSetForeground
        threading.Thread(target=MsgBox.show, args=(msgbox_title, msgbox_message, msgbox_style), daemon=True).start()

    @classmethod
    def populate(cls, database_entries: list[tuple[Path, UserIP_Settings, dict[str, list[str]]]]):
        """
        Replaces userip_databases with a new set of databases.

        Args:
            database_entries: A list of tuples containing database_path, settings, and user_ips.
        """
        with cls.update_userip_database_lock:
            cls.userip_databases = [
                (database_path, settings, user_ips)
                for database_path, settings, user_ips in database_entries
                if settings.ENABLED
            ]

    @classmethod
    def build(cls):
        """
        Build the userip_infos_by_ip dictionaries from the current databases.
        This method updates the dictionaries without clearing their content entirely, and avoids duplicates.
        """
        with cls.update_userip_database_lock:
            userip_infos_by_ip: dict[str, UserIP] = {}
            unresolved_conflicts: set[str] = set()
            ips_set: set[str] = set()

            for database_path, settings, user_ips in cls.userip_databases:
                for username, ips in user_ips.items():
                    for ip in ips:
                        if ip not in userip_infos_by_ip:
                            userip_infos_by_ip[ip] = UserIP(
                                ip = ip,
                                database_path = database_path,
                                settings = settings,
                                usernames = [username]
                            )
                            ips_set.add(ip)

                        if not userip_infos_by_ip[ip].database_path == database_path:
                            if ip not in cls.notified_ip_conflicts:
                                cls._notify_conflict(userip_infos_by_ip[ip], database_path, username, ip)
                                cls.notified_ip_conflicts.add(ip)
                            unresolved_conflicts.add(ip)
                            continue

                        if username not in userip_infos_by_ip[ip].usernames:
                            userip_infos_by_ip[ip].usernames.append(username)

            resolved_conflicts = cls.notified_ip_conflicts - unresolved_conflicts
            for resolved_ip in resolved_conflicts:
                cls.notified_ip_conflicts.remove(resolved_ip)

            cls.userip_infos_by_ip = userip_infos_by_ip
            cls.ips_set = ips_set

    @classmethod
    def get_userip_database_filepaths(cls):
        with cls.update_userip_database_lock:
            return [database_path for database_path, _, _ in cls.userip_databases]

    @classmethod
    def get_userip_info(cls, ip: str):
        """Returns a UserIP object for the specified IP."""
        with cls.update_userip_database_lock:
            return cls.userip_infos_by_ip.get(ip)

    @classmethod
    def update_player_userip_info(cls, player: Player):
        """
        Updates the player's UserIP data using the information from UserIP_Databases.

        Args:
            player: The player object with 'ip' and 'userip' attributes.
        """
        if userip_info := cls.get_userip_info(player.ip):
            player.userip.database_path = userip_info.database_path
            player.userip.settings = userip_info.settings
            player.userip.usernames = userip_info.usernames
            return True
        return False

def is_pyinstaller_compiled():
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")  # https://pyinstaller.org/en/stable/runtime-information.html

def title(title: str):
    print(f"\033]0;{title}\007", end="")

def cls():
    print("\033c", end="")

def take(n: int, input_list: list[Any]):
    """Return first n items from the given input list."""
    return input_list[:n]

def tail(n: int, input_list: list[Any]):
    """Return last n items from the given input list."""
    return input_list[-n:]

def concat_lists_no_duplicates(*lists: list[Any]):
    """
    Concatenates multiple lists while removing duplicates and preserving order.

    Args:
        *lists: One or more lists to concatenate.
    """
    unique_list: list[Any] = []
    seen = set()

    for lst in lists:
        for item in lst:
            if item not in seen:
                unique_list.append(item)
                seen.add(item)

    return unique_list

def pluralize(variable: int):
    return "s" if variable > 1 else ""

def hex_to_int(hex_string: str):
    return int(hex_string, 16)

def is_hex(string: str):
    try:
        int(string, 16)
        return True
    except (ValueError, TypeError):
        return False

def is_ipv4_address(ip_address: str):
    try:
        return IPv4Address(ip_address).version == 4
    except AddressValueError:
        return False

def is_mac_address(mac_address: str):
    from Modules.constants.standard import RE_MAC_ADDRESS_PATTERN
    return bool(RE_MAC_ADDRESS_PATTERN.match(mac_address))

def is_private_device_ipv4(ip_address: str):
    return IPv4Address(ip_address).is_private

def is_valid_non_special_ipv4(ip_address: str):
    try:
        ipv4_obj = IPv4Address(ip_address)
    except AddressValueError:
        return False

    if (
        not ipv4_obj.version == 4
        or ipv4_obj.packed[-1] == 255
        or ipv4_obj.is_link_local # might wants to disable this
        or ipv4_obj.is_loopback
        or ipv4_obj.is_reserved
        or ipv4_obj.is_unspecified
        or ipv4_obj.is_global
        or ipv4_obj.is_multicast
    ):
        return False

    return True

def get_pid_by_path(filepath: Path):
    for process in psutil.process_iter(["pid", "exe"]):
        if process.info["exe"] == str(filepath.absolute()):
            return process.pid
    return None

def get_mac_address_organization_name(mac_address: Optional[str]):
    if mac_address is None:
        return None

    oui_or_mal_infos: list[dict[str, str]] = mac_lookup.lookup(mac_address)
    if oui_or_mal_infos is None:
        return None

    for oui_or_mal in oui_or_mal_infos:
        organization_name = oui_or_mal["organization_name"]
        if not organization_name == "":
            return organization_name

    return None

def get_filtered_tshark_interfaces():
    """
    Retrieves a list of available TShark interfaces, excluding a list of exclusions.

    Returns:
        A list of tuples containing:
        - Index (str)
        - Device name (str)
        - Interface name (str)
    """
    from Modules.constants.standard import EXCLUDED_CAPTURE_NETWORK_INTERFACES

    def process_stdout(stdout: str):
        return stdout.strip().split(" ", maxsplit=2)

    stdout = subprocess.check_output([
        tshark_path, "-D"
    ], text=True, encoding="utf-8")

    if not isinstance(stdout, str):
        raise TypeError(f'Expected "str", got "{type(stdout).__name__}"')

    interfaces: list[tuple[str, str, str]] = []
    for parts in map(process_stdout, stdout.splitlines()):
        if len(parts) == 3:
            index = parts[0].removesuffix(".")
            device_name = parts[1]
            name = parts[2].removeprefix("(").removesuffix(")")

            if name in EXCLUDED_CAPTURE_NETWORK_INTERFACES:
                continue

            interfaces.append((index, device_name, name))

    return interfaces

def get_arp_table():
    import win32com
    from win32com.client import CDispatch

    objWMI = win32com.client.GetObject("winmgmts:\\\\.\\root\\StandardCimv2")
    arp_entries = objWMI.ExecQuery("SELECT * FROM MSFT_NetNeighbor WHERE AddressFamily=2")
    if not isinstance(arp_entries, CDispatch):
        raise TypeError(f'Expected "CDispatch", got "{type(mac_address).__name__}"')

    cached_arp_dict: dict[int, list[dict[str, str]]] = {}

    for entry in arp_entries:
        if not isinstance(entry, CDispatch):
            raise TypeError(f'Expected "CDispatch", got "{type(mac_address).__name__}"')

        interface_index = entry.InterfaceIndex
        if not isinstance(interface_index, int):
            raise TypeError(f'Expected "int", got "{type(mac_address).__name__}"')
        ip_address = entry.IPAddress
        if not isinstance(ip_address, str):
            raise TypeError(f'Expected "str", got "{type(ip_address).__name__}"')
        mac_address = entry.LinkLayerAddress
        if not isinstance(mac_address, str):
            raise TypeError(f'Expected "str", got "{type(mac_address).__name__}"')

        if not ip_address or not mac_address or not interface_index:
            continue

        # Append ARP info directly to the dictionary entry
        cached_arp_dict.setdefault(interface_index, []).append({
            "ip_address": ip_address,
            "mac_address": mac_address
        })

    return cached_arp_dict

def iterate_network_adapter_details(**kwargs):
    """Yields network adapter info using WMI."""
    interfaces: list[_wmi_object] = wmi_namespace.Win32_NetworkAdapter(**kwargs)
    if not isinstance(interfaces, list):
        raise TypeError(f'Expected "list", got "{type(interfaces).__name__}"')

    for interface in interfaces:
        if not isinstance(interface, _wmi_object):
            raise TypeError(f'Expected "_wmi_object", got "{type(interface).__name__}"')

        yield(interface)

def iterate_network_ip_details(**kwargs):
    """Yields network IP address info using WMI."""
    # Get network adapter configurations
    configurations: list[_wmi_object] = wmi_namespace.Win32_NetworkAdapterConfiguration(**kwargs)
    if not isinstance(configurations, list):
        raise TypeError(f'Expected "list", got "{type(configurations).__name__}"')

    for configuration in configurations:
        if not isinstance(configuration, _wmi_object):
            raise TypeError(f'Expected "_wmi_object", got "{type(configuration).__name__}"')

        yield(configuration)

def format_mac_address(mac_address: str):
    if not is_mac_address(mac_address):
        stdout_crash_text = textwrap.dedent(f"""
            ERROR:
                Developer didn't expect this scenario to be possible.

            INFOS:
                It seems like a MAC address does not follow
                \"xx:xx:xx:xx:xx:xx\" or \"xx-xx-xx-xx-xx-xx\"
                format.

            DEBUG:
                mac_address: {mac_address}
        """.removeprefix("\n").removesuffix("\n"))
        terminate_script("EXIT", stdout_crash_text, stdout_crash_text)

    return mac_address.replace("-", ":").upper()

def update_and_initialize_geolite2_readers():
    def update_geolite2_databases():
        from Modules.constants.standalone import GITHUB_RELEASE_API__GEOLITE2 # TODO: Implement adding: `, GITHUB_RELEASE_API__GEOLITE2__BACKUP` in case the first one fails.
        from Modules.constants.standard import GEOLITE2_DATABASES_FOLDER_PATH

        geolite2_version_file_path = GEOLITE2_DATABASES_FOLDER_PATH / "version.json"
        geolite2_databases: dict[str, dict[str, Optional[str]]] = {
            f"GeoLite2-{db}.mmdb": {
                "current_version": None,
                "last_version": None,
                "download_url": None
            }
            for db in ("ASN", "City", "Country")
        }

        try:
            with geolite2_version_file_path.open("r", encoding="utf-8") as f:
                loaded_data = json.load(f)
        except FileNotFoundError:
            pass
        else:
            if isinstance(loaded_data, dict):
                for database_name, database_info in loaded_data.items():
                    if not isinstance(database_name, str):
                        continue
                    if not isinstance(database_info, dict):
                        continue
                    if not database_name in geolite2_databases:
                        continue

                    geolite2_databases[database_name]["current_version"] = database_info.get("version", None)

        try:
            response = s.get(GITHUB_RELEASE_API__GEOLITE2)
        except Exception as e:
            return {
                "exception": e,
                "url": GITHUB_RELEASE_API__GEOLITE2,
                "http_code": None
            }
        if response.status_code != 200:
            return {
                "exception": None,
                "url": GITHUB_RELEASE_API__GEOLITE2,
                "http_code": response.status_code
            }

        release_data = response.json()
        if not isinstance(release_data, dict):
            raise TypeError(f'Expected "dict" object, got "{type(release_data).__name__}"')

        for asset in release_data["assets"]:
            asset_name = asset["name"]
            if not isinstance(asset_name, str):
                continue
            if not asset_name in geolite2_databases:
                continue

            geolite2_databases[asset_name].update({
                "last_version": asset["updated_at"],
                "download_url": asset["browser_download_url"]
            })

        failed_fetching_flag_list: list[str] = []
        for database_name, database_info in geolite2_databases.items():
            if database_info["last_version"]:
                if not database_info["current_version"] == database_info["last_version"]:
                    try:
                        response = s.get(database_info["download_url"])
                    except Exception as e:
                        return {
                            "exception": e,
                            "url": database_info["download_url"],
                            "http_code": None
                        }
                    if response.status_code != 200:
                        return {
                            "exception": None,
                            "url": database_info["download_url"],
                            "http_code": response.status_code
                        }
                    if not isinstance(response.content, bytes):
                        raise TypeError(f'Expected "bytes" object, got "{type(response.content).__name__}"')

                    GEOLITE2_DATABASES_FOLDER_PATH.mkdir(parents=True, exist_ok=True)  # Create directory if it doesn't exist
                    destination_file_path = GEOLITE2_DATABASES_FOLDER_PATH / database_name

                    # [Bug-Fix]: https://github.com/BUZZARDGTA/Session-Sniffer/issues/28
                    if destination_file_path.is_file():
                        if hashlib.sha256(destination_file_path.read_bytes()).hexdigest() == hashlib.sha256(response.content).hexdigest():
                            geolite2_databases[database_name]["current_version"] = database_info["last_version"]
                        else:
                            temp_path = Path(tempfile.gettempdir()) / database_name
                            temp_path.write_bytes(response.content)

                            try:
                                shutil.move(temp_path, destination_file_path)
                            except OSError as e:
                                # The file is currently open and in use by another process. Abort updating this db.
                                if e.winerror == 1224:  # https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-
                                    if temp_path.is_file():
                                        temp_path.unlink()
                                    geolite2_databases[database_name]["current_version"] = database_info["current_version"]
                    else:
                        destination_file_path.write_bytes(response.content)
                        geolite2_databases[database_name]["current_version"] = database_info["last_version"]
            else:
                failed_fetching_flag_list.append(database_name)

        if failed_fetching_flag_list:
            msgbox_title = TITLE
            msgbox_message = textwrap.indent(textwrap.dedent(f"""
                ERROR:
                    Failed fetching MaxMind \"{'\", \"'.join(failed_fetching_flag_list)}\" database{pluralize(len(failed_fetching_flag_list))}.

                INFOS:
                    These MaxMind GeoLite2 database{pluralize(len(failed_fetching_flag_list))} will not be updated.

                DEBUG:
                    GITHUB_RELEASE_API__GEOLITE2={GITHUB_RELEASE_API__GEOLITE2}
                    failed_fetching_flag_list={failed_fetching_flag_list}
            """.removeprefix("\n").removesuffix("\n")), "    ")
            msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.SystemModal | MsgBox.Style.MsgBoxSetForeground
            threading.Thread(target=MsgBox.show, args=(msgbox_title, msgbox_message, msgbox_style), daemon=True).start()

        # Create the data dictionary, where each name maps to its version info
        data = {
            name: {"version": info["current_version"]}
            for name, info in geolite2_databases.items()
        }

        # Convert the data to a JSON formatted string with proper indentation
        json_data = json.dumps(data, indent=4)

        # Write the JSON formatted string to the GeoLite2 version file
        geolite2_version_file_path.write_text(json_data, encoding="utf-8")

        return {
            "exception": None,
            "url": None,
            "http_code": None
        }

    def initialize_geolite2_readers():
        from Modules.constants.standard import GEOLITE2_DATABASES_FOLDER_PATH

        try:
            geolite2_asn_reader = geoip2.database.Reader(GEOLITE2_DATABASES_FOLDER_PATH / "GeoLite2-ASN.mmdb")
            geolite2_city_reader = geoip2.database.Reader(GEOLITE2_DATABASES_FOLDER_PATH / "GeoLite2-City.mmdb")
            geolite2_country_reader = geoip2.database.Reader(GEOLITE2_DATABASES_FOLDER_PATH / "GeoLite2-Country.mmdb")

            geolite2_asn_reader.asn("1.1.1.1")
            geolite2_city_reader.city("1.1.1.1")
            geolite2_country_reader.country("1.1.1.1")
        except Exception as e:
            geolite2_asn_reader = None
            geolite2_city_reader = None
            geolite2_country_reader = None

            exception = e
        else:
            exception = None

        return exception, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader

    update_geolite2_databases__dict = update_geolite2_databases()
    exception__initialize_geolite2_readers, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = initialize_geolite2_readers()

    show_error = False
    msgbox_message = ""

    if update_geolite2_databases__dict["exception"]:
        msgbox_message += f"Exception Error: {update_geolite2_databases__dict['exception']}\n\n"
        show_error = True
    if update_geolite2_databases__dict["url"]:
        msgbox_message += f"Error: Failed fetching url: \"{update_geolite2_databases__dict['url']}\"."
        if update_geolite2_databases__dict["http_code"]:
            msgbox_message += f" (http_code: {update_geolite2_databases__dict['http_code']})"
        msgbox_message += "\nImpossible to keep Maxmind's GeoLite2 IP to Country, City and ASN resolutions feature up-to-date.\n\n"
        show_error = True

    if exception__initialize_geolite2_readers:
        msgbox_message += f"Exception Error: {exception__initialize_geolite2_readers}\n\n"
        msgbox_message += "Now disabling MaxMind's GeoLite2 IP to Country, City and ASN resolutions feature.\n"
        msgbox_message += "Countrys, Citys and ASN from players won't shows up from the players fields."
        geoip2_enabled = False
        show_error = True
    else:
        geoip2_enabled = True

    if show_error:
        msgbox_title = TITLE
        msgbox_message = msgbox_message.rstrip("\n")
        msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
        MsgBox.show(msgbox_title, msgbox_message, msgbox_style)

    return geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader

def parse_settings_ini_file(ini_path: Path, values_handling: Literal["first", "last", "all"]):
    from Modules.constants.standard import RE_SETTINGS_INI_PARSER_PATTERN

    def process_ini_line_output(line: str):
        return line.rstrip("\n")

    if not ini_path.exists():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(ini_path.absolute()))
    if not ini_path.is_file():
        raise InvalidFileError(str(ini_path.absolute()))

    ini_data = ini_path.read_text("utf-8")

    need_rewrite_ini = False
    ini_database: dict[str, str | list[str]] = {}

    for line in map(process_ini_line_output, ini_data.splitlines(keepends=False)):
        corrected_line = line.strip()
        if not corrected_line == line:
            need_rewrite_ini = True

        match = RE_SETTINGS_INI_PARSER_PATTERN.search(corrected_line)
        if not match:
            continue
        setting_name = match.group("key")
        if not isinstance(setting_name, str):
            raise TypeError(f'Expected "str" object, got "{type(setting_name).__name__}"')
        setting_value = match.group("value")
        if not isinstance(setting_value, str):
            raise TypeError(f'Expected "str" object, got "{type(setting_value).__name__}"')

        corrected_setting_name = setting_name.strip()
        if corrected_setting_name == "":
            continue
        elif not corrected_setting_name == setting_name:
            need_rewrite_ini = True

        corrected_setting_value = setting_value.strip()
        if corrected_setting_value == "":
            continue
        elif not corrected_setting_value == setting_value:
            need_rewrite_ini = True

        if values_handling == "first":
            if corrected_setting_name not in ini_database:
                ini_database[corrected_setting_name] = corrected_setting_value
        elif values_handling == "last":
            ini_database[corrected_setting_name] = corrected_setting_value
        elif values_handling == "all":
            if corrected_setting_name in ini_database:
                ini_database[corrected_setting_name].append(corrected_setting_value)
            else:
                ini_database[corrected_setting_name] = [corrected_setting_value]

    return ini_database, need_rewrite_ini

def is_file_need_newline_ending(file: Union[str, Path]):
    if isinstance(file, Path):
        file_path = file
    else:
        file_path = Path(file)

    if file_path.stat().st_size == 0:
        return False

    return not file.read_bytes().endswith(b"\n")

def write_lines_to_file(file: Path, mode: Literal["w", "x", "a"], lines: list[str]):
    """
    Writes or appends a list of lines to a file, ensuring proper newline handling.

    Args:
        file: The path to the file.
        mode: The file mode ('w', 'x' or 'a').
        lines: A list of lines to write to the file.
    """
    # Copy the input lines to avoid modifying the original list
    content = lines[:]

    # If the content list is empty, exit early without writing to the file
    if not content:
        return

    # If appending to a file, ensure a leading newline is added if the file exists, otherwise creates it.
    if mode == "a":
        if file.is_file():
            if is_file_need_newline_ending(file):
                content.insert(0, "")
        else:
            file.touch()

    # Ensure the last line ends with a newline character
    if not content[-1].endswith("\n"):
        content[-1] += "\n"

    # Write content to the file
    with file.open(mode, encoding="utf-8") as f:
        f.writelines(content)

def terminate_process_tree(pid: int = None):
    """Terminates the process with the given PID and all its child processes.
       Defaults to the current process if no PID is specified."""
    pid = pid or psutil.Process().pid

    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        psutil.wait_procs(children, timeout=5)
        try:
            parent.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        parent.wait(5)
    except psutil.NoSuchProcess:
        pass

def check_case_insensitive_and_exact_match(input_value: str, custom_values_list: list[str]):
    """
    Checks if the input value matches any string in the list case-insensitively, and whether it also matches exactly (case-sensitive).

    It also returns the correctly capitalized version of the matched value from the list if a case-insensitive match is found.

    Returns a tuple of three values:
    - The first boolean is True if a case-insensitive match is found.
    - The second boolean is True if the exact case-sensitive match is found.
    - The third value is the correctly capitalized version of the matched string if found, otherwise None.
    """
    case_insensitive_match = False
    case_sensitive_match = False
    normalized_match = None

    lowered_input_value = input_value.lower()
    for value in custom_values_list:
        if value.lower() == lowered_input_value:
            case_insensitive_match = True
            normalized_match = value
            if value == input_value:
                case_sensitive_match = True
                break

    return case_insensitive_match, case_sensitive_match, normalized_match

def custom_str_to_bool(string: str, only_match_against: Optional[bool] = None):
    """
    This function returns the boolean value represented by the string for lowercase or any case variation;\n
    otherwise, it raises an \"InvalidBooleanValueError\".

    Args:
        string: The boolean string to be checked.
        only_match_against (optional): If provided, the only boolean value to match against.
    """
    need_rewrite_current_setting = False
    resolved_value = None

    string_lower = string.lower()

    if string_lower == "true":
        resolved_value = True
    elif string_lower == "false":
        resolved_value = False

    if resolved_value is None:
        raise InvalidBooleanValueError("Input is not a valid boolean value")

    if (
        only_match_against is not None
        and only_match_against is not resolved_value
    ):
        raise InvalidBooleanValueError("Input does not match the specified boolean value")

    if not string == str(resolved_value):
        need_rewrite_current_setting = True

    return resolved_value, need_rewrite_current_setting

def custom_str_to_nonetype(string: str):
    """
    This function returns the NoneType value represented by the string for lowercase or any case variation; otherwise, it raises an \"InvalidNoneTypeValueError\".

    Args:
        string: The NoneType string to be checked.
    """
    if not string.lower() == "none":
        raise InvalidNoneTypeValueError("Input is not a valid NoneType value")

    is_string_literal_none = string == "None"
    return None, is_string_literal_none

colorama.init(autoreset=True)

if is_pyinstaller_compiled():
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

if not is_pyinstaller_compiled():
    import importlib.metadata

    cls()
    title(f'Checking that your Python packages versions matches with file "requirements.txt" - {TITLE}')
    print(f'\nChecking that your Python packages versions matches with file "requirements.txt" ...\n')

    def check_packages_version(third_party_packages: dict[str, str]):
        outdated_packages: list[tuple[str, str, str]] = []

        for package_name, required_version in third_party_packages.items():
            installed_version = importlib.metadata.version(package_name)
            if not installed_version == required_version:
                outdated_packages.append((package_name, installed_version, required_version))

        return outdated_packages

    third_party_packages = {
        "colorama": "0.4.6",
        "dnspython": "2.7.0",
        "geoip2": "4.8.1",
        "prettytable": "3.12.0",
        "psutil": "6.1.0",
        "pypresence": "4.3.0",
        "PyQt6": "6.8.0",
        "pywin32": "308",
        "QDarkStyle": "3.2.3",
        "requests": "2.32.3",
        "rich": "13.9.4",
        "urllib3": "2.2.3",
        "WMI": "1.5.1"
    }

    outdated_packages: list[tuple[str, str, str]] = check_packages_version(third_party_packages)
    if outdated_packages:
        msgbox_message = "Your following packages are not up to date:\n\n"
        msgbox_message += f"Package Name: Installed version --> Required version\n"

        # Iterate over outdated packages and add each package's information to the message box text
        for package_name, installed_version, required_version in outdated_packages:
            msgbox_message += f"{package_name}: {installed_version} --> {required_version}\n"

        # Add additional message box text
        msgbox_message += f"\nKeeping your packages synced with \"{TITLE}\" ensures smooth script execution and prevents compatibility issues."
        msgbox_message += "\n\nDo you want to ignore this warning and continue with script execution?"

        # Show message box
        msgbox_style = MsgBox.Style.YesNo | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
        msgbox_title = TITLE
        errorlevel = MsgBox.show(msgbox_title, msgbox_message, msgbox_style)
        if errorlevel != MsgBox.ReturnValues.IDYES:
            terminate_script("EXIT")

cls()
title(f'Applying your custom settings from "Settings.ini" - {TITLE}')
print('\nApplying your custom settings from "Settings.ini" ...\n')
Settings.load_from_settings_file(SETTINGS_PATH)

cls()
title(f"Searching for a new update - {TITLE}")
print("\nSearching for a new update ...\n")
from Modules.constants.standalone import GITHUB_RELEASES_URL

CURRENT_VERSION = Version(VERSION)

try:
    response = s.get("https://raw.githubusercontent.com/BUZZARDGTA/Session-Sniffer/version/versions.json")
    response.raise_for_status()
except:
    msgbox_title = TITLE
    msgbox_message = textwrap.dedent(f"""
        ERROR:
        Failed to check for updates.

        Do you want to open the \"{TITLE}\" project download page ?
        You can then download and run the latest version from there.
    """.removeprefix("\n").removesuffix("\n"))
    msgbox_style = MsgBox.Style.YesNo | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
    errorlevel = MsgBox.show(msgbox_title, msgbox_message, msgbox_style)
    if errorlevel == MsgBox.ReturnValues.IDYES:
        webbrowser.open(GITHUB_RELEASES_URL)
        terminate_script("EXIT")
else:
    versions_json: dict[str, str] = response.json()
    if not isinstance(versions_json, dict):
        raise TypeError(f'Expected "dict" object, got "{type(versions_json).__name__}"')

    # Get versions from the response
    latest_stable_version = Version(versions_json["Stable"])
    latest_alpha_version = Version(versions_json["Alpha"])

    # Check for updates based on the current version
    updater = Updater(CURRENT_VERSION)
    is_new_stable_version_available = updater.check_for_update(latest_stable_version)
    is_new_alpha_version_available = updater.check_for_update(latest_alpha_version)

    # Determine which version to display based on the user's channel setting
    if is_new_stable_version_available or (Settings.UPDATER_CHANNEL == "Alpha" and is_new_alpha_version_available):
        update_channel = "alpha" if (Settings.UPDATER_CHANNEL == "Alpha" and is_new_alpha_version_available) else "stable"
        latest_version = latest_alpha_version if (Settings.UPDATER_CHANNEL == "Alpha" and is_new_alpha_version_available) else latest_stable_version

        msgbox_title = TITLE
        msgbox_message = textwrap.dedent(f"""
            New {update_channel} version found. Do you want to update?

            Current version: {CURRENT_VERSION}
            Latest version: {latest_version}
        """.removeprefix("\n").removesuffix("\n"))

        msgbox_style = MsgBox.Style.YesNo | MsgBox.Style.Question | MsgBox.Style.MsgBoxSetForeground
        errorlevel = MsgBox.show(msgbox_title, msgbox_message, msgbox_style)

        if errorlevel == MsgBox.ReturnValues.IDYES:
            webbrowser.open(GITHUB_RELEASES_URL)
            terminate_script("EXIT")

del GITHUB_RELEASES_URL

cls()
title(f'Checking that "Npcap" driver is installed on your system - {TITLE}')
print('\nChecking that "Npcap" driver is installed on your system ...\n')
from Modules.constants.local import SETUP_PATH

while not is_npcap_installed():
    webbrowser.open("https://nmap.org/npcap/")
    msgbox_title = TITLE
    msgbox_message = textwrap.dedent(f"""
        ERROR:
        Could not detect \"Npcap\" driver installed on your system.

        Opening the \"Npcap\" setup installer for you.
    """.removeprefix("\n").removesuffix("\n"))
    msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
    MsgBox.show(msgbox_title, msgbox_message, msgbox_style)

    subprocess.run([SETUP_PATH / "npcap-1.78.exe"], shell=True)

del SETUP_PATH

cls()
title(f'Applying your custom settings from "Settings.ini" - {TITLE}')
print('\nApplying your custom settings from "Settings.ini" ...\n')
Settings.load_from_settings_file(SETTINGS_PATH)

cls()
title(f'\nVerifying "Tshark (Wireshark) v{TSHARK_RECOMMENDED_VERSION_NUMBER}" in script directories and version match - {TITLE}')
print(f'\nVerifying "Tshark (Wireshark) v{TSHARK_RECOMMENDED_VERSION_NUMBER}" in script directories and version match ...\n')

from Modules.constants.local import BIN_PATH
from Modules.constants.standalone import GITHUB_RELEASES_URL

while True:
    try:
        tshark_path, tshark_version = validate_tshark_path(BIN_PATH / "WiresharkPortable64/App/Wireshark/tshark.exe")
        break
    except TSharkNotFoundException:
        webbrowser.open(GITHUB_RELEASES_URL)

        msgbox_title = TITLE
        msgbox_message = textwrap.dedent(f"""
            ERROR:
            \"TShark\" could not be found within the script directories.

            Opening {TITLE} download page for you.
            Please download and reinstall it, then restart the application.
        """.removeprefix("\n").removesuffix("\n"))
        msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
        MsgBox.show(msgbox_title, msgbox_message, msgbox_style)
        terminate_script("EXIT")
    except TSharkVersionNotFoundException:
        webbrowser.open(GITHUB_RELEASES_URL)

        msgbox_title = TITLE
        msgbox_message = textwrap.dedent(f"""
            ERROR:
            Could not determine the version of \"TShark (Wireshark)\".

            Opening {TITLE} download page for you.
            Please download and reinstall it, then restart the application.
        """).strip()
        msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
        MsgBox.show(msgbox_title, msgbox_message, msgbox_style)
        terminate_script("EXIT")
    except InvalidTSharkVersionException as unsupported_tshark:
        webbrowser.open(GITHUB_RELEASES_URL)

        msgbox_title = TITLE
        msgbox_message = textwrap.dedent(f"""
            ERROR:
            Detected an unsupported \"Tshark (Wireshark)\" version installed on your system.

            Detected version: {unsupported_tshark.version}
            Recommended version: {TSHARK_RECOMMENDED_FULL_VERSION}

            Opening {TITLE} download page for you.
            Please download and reinstall it, then restart the application.
        """.removeprefix("\n").removesuffix("\n"))
        msgbox_style = MsgBox.Style.AbortRetryIgnore | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
        errorlevel = MsgBox.show(msgbox_title, msgbox_message, msgbox_style)
        if errorlevel == MsgBox.ReturnValues.IDABORT:
            terminate_script("EXIT")
        elif errorlevel == MsgBox.ReturnValues.IDIGNORE:
            tshark_path = unsupported_tshark.path
            tshark_version = unsupported_tshark.version
            break

del BIN_PATH, GITHUB_RELEASES_URL

cls()
title(f"Initializing and updating MaxMind's GeoLite2 Country, City and ASN databases - {TITLE}")
print("\nInitializing and updating MaxMind's GeoLite2 Country, City and ASN databases ...\n")
geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = update_and_initialize_geolite2_readers()

cls()
title(f"Initializing MacLookup module - {TITLE}")
print(f"\nInitializing MacLookup module ...\n")
mac_lookup = MacLookup(bypass_fetch_error=True)

cls()
title(f"Capture network interface selection - {TITLE}")
print(f"\nCapture network interface selection ...\n")
wmi_namespace: _wmi_namespace = wmi.WMI()
if not isinstance(wmi_namespace, _wmi_namespace):
    raise TypeError(f'Expected "_wmi_namespace" object, got "{type(wmi_namespace).__name__}"')

for _, _, name in get_filtered_tshark_interfaces():
    Interface(name)

net_io_stats = psutil.net_io_counters(pernic=True)
for interface_name, interface_stats in net_io_stats.items():
    i = Interface.get_interface_by_name(interface_name)
    if not i:
        continue

    i.packets_sent = interface_stats.packets_sent
    i.packets_recv = interface_stats.packets_recv

for config in iterate_network_adapter_details():
    i = Interface.get_interface_by_name(config.NetConnectionID)
    if not i:
        continue

    # Filter out interfaces that are not enabled
    if not config.NetEnabled:
        Interface.delete_interface(i)
        continue

    if config.MACAddress is not None:
        if not isinstance(config.MACAddress, str):
            raise TypeError(f'Expected "str" object, got "{type(config.MACAddress).__name__}"')
        if i.mac_address != "N/A":
            stdout_crash_text = textwrap.dedent(f"""
                ERROR:
                    Developer didn't expect this scenario to be possible.

                INFOS:
                    \"WMI\" Python's module returned more then one
                    mac address for a given interface.

                DEBUG:
                    i.interface_name: {i.interface_name}
                    i.mac_address: {i.mac_address}
                    config.MACAddress: {config.MACAddress}
            """.removeprefix("\n").removesuffix("\n"))
            terminate_script("EXIT", stdout_crash_text, stdout_crash_text)
        i.mac_address = config.MACAddress
        i.organization_name = (
            get_mac_address_organization_name(i.mac_address)
            or "N/A"
        )

    if config.InterfaceIndex is not None:
        if not isinstance(config.InterfaceIndex, int):
            raise TypeError(f'Expected "int" object, got "{type(config.InterfaceIndex).__name__}"')
        if i.adapter_properties.InterfaceIndex != "N/A":
            stdout_crash_text = textwrap.dedent(f"""
                ERROR:
                    Developer didn't expect this scenario to be possible.

                INFOS:
                    \"WMI\" Python's module returned more then one
                    index for a given interface.

                DEBUG:
                    i.interface_name: {i.interface_name}
                    config.InterfaceIndex: {config.InterfaceIndex}
            """.removeprefix("\n").removesuffix("\n"))
            terminate_script("EXIT", stdout_crash_text, stdout_crash_text)
        i.adapter_properties.InterfaceIndex = config.InterfaceIndex

    if config.Name is not None:
        if not isinstance(config.Name, str):
            raise TypeError(f'Expected "str" object, got "{type(config.Name).__name__}"')
        i.adapter_properties.Name = config.Name

    if config.Manufacturer is not None:
        if not isinstance(config.Manufacturer, str):
            raise TypeError(f'Expected "str" object, got "{type(config.Manufacturer).__name__}"')
        i.adapter_properties.Manufacturer = config.Manufacturer

for config in iterate_network_ip_details():
    i = Interface.get_interface_by_id(config.InterfaceIndex)
    if not i:
        continue

    # Filter out interfaces that are not enabled
    if not config.IPEnabled:
        Interface.delete_interface(i)
        continue

    if config.IPAddress is not None:
        if not isinstance(config.IPAddress, tuple):
            raise TypeError(f'Expected "tuple" object, got "{type(config.IPAddress).__name__}"')

        for ip in config.IPAddress:
            if not is_ipv4_address(ip):
                continue

            if ip not in i.ip_addresses:
                i.ip_addresses.append(ip)

    if config.MACAddress is not None:
        if not isinstance(config.MACAddress, str):
            raise TypeError(f'Expected "str" object, got "{type(config.MACAddress).__name__}"')
        if i.mac_address != config.MACAddress:
            stdout_crash_text = textwrap.dedent(f"""
                ERROR:
                    Developer didn't expect this scenario to be possible.

                INFOS:
                    An interface IP address has multiple MAC addresses.

                DEBUG:
                    i.interface_name: {i.interface_name}
                    i.mac_address: {i.mac_address}
                    config.MACAddress: {config.MACAddress}
            """.removeprefix("\n").removesuffix("\n"))
            terminate_script("EXIT", stdout_crash_text, stdout_crash_text)
        i.mac_address = config.MACAddress

if Settings.CAPTURE_ARP:
    cached_arp_dict = get_arp_table()

    for cached_arp_interface_index, cached_arp_infos in cached_arp_dict.items():
        i = Interface.get_interface_by_id(cached_arp_interface_index)
        if not i or cached_arp_interface_index != i.adapter_properties.InterfaceIndex:
            continue

        interface_arp_infos: list[dict[str, str]] = []

        # Skip ARP entries with known placeholder MAC addresses
        for entry in cached_arp_infos:
            if entry["mac_address"] in ("00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF"):
                continue

            if is_valid_non_special_ipv4(entry["ip_address"]):
                interface_arp_infos.append({
                    "ip_address": entry["ip_address"],
                    "mac_address": format_mac_address(entry["mac_address"]),
                    "organization_name": (
                        get_mac_address_organization_name(entry["mac_address"])
                        or "N/A"
                    )
                })

        if not interface_arp_infos:
            continue

        for interface_ip_address in i.ip_addresses:
            i.add_arp_infos(interface_arp_infos)

from Modules.capture.interface_selection import InterfaceSelectionData, show_interface_selection_dialog

def get_screen_size(app: QApplication):
    screen = app.primaryScreen()
    size = screen.size()
    return size.width(), size.height()

# Create a QApplication instance
app = QApplication([])  # Passing an empty list for application arguments
app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt6())
screen_width, screen_height = get_screen_size(app)

interfaces_selection_data: list[InterfaceSelectionData] = []

for i in Interface.iterate_safely():
    if (
        Settings.CAPTURE_INTERFACE_NAME is not None
        and Settings.CAPTURE_INTERFACE_NAME.lower() == i.interface_name.lower()
        and not Settings.CAPTURE_INTERFACE_NAME == i.interface_name
    ):
        Settings.CAPTURE_INTERFACE_NAME = i.interface_name
        Settings.reconstruct_settings()

    # Filter out interfaces that are not enabled
    if (i.packets_sent == "N/A" or i.packets_sent == 0) and (i.packets_recv == "N/A" or i.packets_recv == 0) and not i.ip_addresses and i.mac_address == "N/A" and i.adapter_properties.Name == "N/A" and i.adapter_properties.Manufacturer == "N/A":
        Interface.delete_interface(i)
        continue

    if i.adapter_properties.Manufacturer == "N/A":
        manufacturer_or_organization_name = i.organization_name
    else:
        manufacturer_or_organization_name = i.adapter_properties.Manufacturer

    if i.ip_addresses:
        for ip_address in i.ip_addresses:
            interfaces_selection_data.append(InterfaceSelectionData(len(interfaces_selection_data), i.interface_name, i.packets_sent, i.packets_recv, ip_address, i.mac_address, i.adapter_properties.Name, manufacturer_or_organization_name))
    else:
        interfaces_selection_data.append(InterfaceSelectionData(len(interfaces_selection_data), i.interface_name, i.packets_sent, i.packets_recv, "N/A", i.mac_address, i.adapter_properties.Name, manufacturer_or_organization_name))

    if Settings.CAPTURE_ARP:
        for ip in i.ip_addresses:
            arp_infos = i.get_arp_infos()
            if not arp_infos:
                continue

            for arp_info in arp_infos:
                interfaces_selection_data.append(InterfaceSelectionData(len(interfaces_selection_data), i.interface_name, "N/A", "N/A", arp_info["ip_address"], arp_info["mac_address"], i.adapter_properties.Name, arp_info["organization_name"], is_arp=True))

user_interface_selection = None

if (
    # Check if the network interface prompt is disabled
    not Settings.CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT
    # Check if any capture setting is defined
    and any(setting is not None for setting in (Settings.CAPTURE_INTERFACE_NAME, Settings.CAPTURE_MAC_ADDRESS, Settings.CAPTURE_IP_ADDRESS))
):
    max_priority = 0

    for interface in interfaces_selection_data:
        priority = 0

        if Settings.CAPTURE_INTERFACE_NAME is not None:
            if Settings.CAPTURE_INTERFACE_NAME == interface.interface_name:
                priority += 1
        if Settings.CAPTURE_MAC_ADDRESS is not None:
            if Settings.CAPTURE_MAC_ADDRESS == interface.mac_address:
                priority += 1
        #else:
        #    if interface.mac_address == "N/A":
        #        priority += 1
        if Settings.CAPTURE_IP_ADDRESS is not None:
            if Settings.CAPTURE_IP_ADDRESS == interface.ip_address:
                priority += 1
        #else:
        #    if interface.ip_address == "N/A":
        #        priority += 1

        if priority == max_priority: # If multiple matches on the same priority are found we search for the next bigger priority else we prompt the user.
            user_interface_selection = None
        elif priority > max_priority:
            max_priority = priority
            user_interface_selection = interface.index

if user_interface_selection is None:
    selected_interface_data = show_interface_selection_dialog(screen_width, screen_height, interfaces_selection_data)
    if selected_interface_data is None:
        terminate_script("EXIT")
        sys.exit(0) # This is just a hack to fix following VSCode type hinting.
    user_interface_selection = selected_interface_data.index

cls()
title(f"Initializing addresses and establishing connection to your PC / Console - {TITLE}")
print(f"\nInitializing addresses and establishing connection to your PC / Console ...\n")
need_rewrite_settings = False
fixed__capture_mac_address = interfaces_selection_data[user_interface_selection].mac_address if interfaces_selection_data[user_interface_selection].mac_address != "N/A" else None
fixed__capture_ip_address = interfaces_selection_data[user_interface_selection].ip_address if interfaces_selection_data[user_interface_selection].ip_address != "N/A" else None

if Settings.CAPTURE_INTERFACE_NAME is None:
    Settings.CAPTURE_INTERFACE_NAME = interfaces_selection_data[user_interface_selection].interface_name
    need_rewrite_settings = True
elif not Settings.CAPTURE_INTERFACE_NAME == interfaces_selection_data[user_interface_selection].interface_name:
    Settings.CAPTURE_INTERFACE_NAME = interfaces_selection_data[user_interface_selection].interface_name
    need_rewrite_settings = True

if not Settings.CAPTURE_MAC_ADDRESS == fixed__capture_mac_address:
    Settings.CAPTURE_MAC_ADDRESS = fixed__capture_mac_address
    need_rewrite_settings = True

if not Settings.CAPTURE_IP_ADDRESS == fixed__capture_ip_address:
    Settings.CAPTURE_IP_ADDRESS = fixed__capture_ip_address
    need_rewrite_settings = True

if need_rewrite_settings:
    Settings.reconstruct_settings()

capture_filter: list[str] = ["ip", "udp"]
display_filter: list[str] = []
excluded_protocols: list[str] = []

if Settings.CAPTURE_IP_ADDRESS:
    capture_filter.append(f"((src host {Settings.CAPTURE_IP_ADDRESS} and (not (dst net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))) or (dst host {Settings.CAPTURE_IP_ADDRESS} and (not (src net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))))")

force_enable_capture_vpn_mode = False
if not Settings.CAPTURE_VPN_MODE:
    from Modules.capture.utils.check_tshark_filters import check_broadcast_multicast_support

    result = check_broadcast_multicast_support(tshark_path, Settings.CAPTURE_INTERFACE_NAME)
    if result.broadcast_supported and result.multicast_supported:
        capture_filter.append("not (broadcast or multicast)")
    else:
        force_enable_capture_vpn_mode = True

capture_filter.append("not (portrange 0-1023 or port 5353)")

if Settings.CAPTURE_PROGRAM_PRESET:
    if Settings.CAPTURE_PROGRAM_PRESET == "GTA5":
        capture_filter.append("(len >= 71 and len <= 1032)")
    elif Settings.CAPTURE_PROGRAM_PRESET == "Minecraft":
        capture_filter.append("(len >= 49 and len <= 1498)")

    # If the <CAPTURE_PROGRAM_PRESET> setting is set, automatically blocks RTCP connections.
    # In case RTCP can be useful to get someone IP, I decided not to block them without using a <CAPTURE_PROGRAM_PRESET>.
    # RTCP is known to be for example the Discord's server IP while you are in a call there.
    # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
    # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
    # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
    # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
    excluded_protocols.append("rtcp")

if Settings.CAPTURE_BLOCK_THIRD_PARTY_SERVERS:
    capture_filter.append(f"not (net {' or '.join(ThirdPartyServers.get_all_ip_ranges())})")

    # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
    # But there can be a lot more, those are just a couples I could find on my own usage.
    excluded_protocols.extend(["ssdp", "raknet", "dtls", "nbns", "pcp", "bt-dht", "uaudp", "classicstun", "dhcp", "mdns", "llmnr"])

if excluded_protocols:
    display_filter.append(
        f"not ({' or '.join(excluded_protocols)})"
    )

if Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER:
    capture_filter.insert(0, Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER)

if Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER:
    display_filter.insert(0, Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER)

CAPTURE_FILTER = " and ".join(capture_filter) if capture_filter else None
DISPLAY_FILTER = " and ".join(display_filter) if display_filter else None

capture = PacketCapture(
    interface = Settings.CAPTURE_INTERFACE_NAME,
    capture_filter = CAPTURE_FILTER,
    display_filter = DISPLAY_FILTER,
    tshark_path = tshark_path,
    tshark_version = tshark_version
)

userip_logging_file_write_lock = threading.Lock()
gui_closed__event = threading.Event()

def process_userip_task(player: Player, connection_type: Literal["connected", "disconnected"]):
    with Threads_ExceptionHandler():
        def suspend_process_for_duration_or_mode(process_pid: int, duration_or_mode: Union[int, float, Literal["Auto", "Manual"]]):
            """
            Suspends the specified process for a given duration or until a specified condition is met.

            ### Parameters:
            * process_pid: The process ID of the process to be suspended.
            * duration_or_mode:
                - If an integer or float, it specifies the duration (in seconds) to suspend the process.
                - If set to \"Manual\", the process will be suspended indefinitely until the user manually resume it.
                - If set to \"Auto\", the process will be suspended until the player is flagged as \"disconnected\", after which it is resumed automatically.
            """
            process = psutil.Process(process_pid)
            process.suspend()

            if isinstance(duration_or_mode, (int, float)):
                gui_closed__event.wait(duration_or_mode)
                process.resume()
                return

            if duration_or_mode == "Manual":
                return
            elif duration_or_mode == "Auto":
                while not player.datetime.left:
                    gui_closed__event.wait(0.1)
                process.resume()
                return

        from Modules.constants.standard import USERIP_LOGGING_PATH
        from Modules.constants.local import TTS_PATH

        # We wants to run this as fast as possible so it's on top of the function.
        if connection_type == "connected":
            if player.userip.settings.PROTECTION:
                if player.userip.settings.PROTECTION == "Suspend_Process":
                    if process_pid := get_pid_by_path(player.userip.settings.PROTECTION_PROCESS_PATH):
                        threading.Thread(target=suspend_process_for_duration_or_mode, args=(process_pid, player.userip.settings.PROTECTION_SUSPEND_PROCESS_MODE), daemon=True).start()
                elif player.userip.settings.PROTECTION in ("Exit_Process", "Restart_Process"):
                    if isinstance(player.userip.settings.PROTECTION_PROCESS_PATH, Path):
                        if process_pid := get_pid_by_path(player.userip.settings.PROTECTION_PROCESS_PATH):
                            terminate_process_tree(process_pid)

                            if player.userip.settings.PROTECTION == "Restart_Process" and isinstance(player.userip.settings.PROTECTION_RESTART_PROCESS_PATH, Path):
                                os.startfile(str(player.userip.settings.PROTECTION_RESTART_PROCESS_PATH.absolute()))
                elif player.userip.settings.PROTECTION == "Shutdown_PC":
                    subprocess.Popen(["shutdown", "/s"])
                elif player.userip.settings.PROTECTION == "Restart_PC":
                    subprocess.Popen(["shutdown", "/r"])

        if player.userip.settings.VOICE_NOTIFICATIONS:
            if player.userip.settings.VOICE_NOTIFICATIONS == "Male":
                voice_name = "Liam"
            elif player.userip.settings.VOICE_NOTIFICATIONS == "Female":
                voice_name = "Jane"
            tts_file_path = TTS_PATH / f"{voice_name} ({connection_type}).wav"

            if not tts_file_path.exists():
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(tts_file_path.absolute()))
            if not tts_file_path.is_file():
                raise InvalidFileError(str(tts_file_path.absolute()))

            winsound.PlaySound(tts_file_path, winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)

        if connection_type == "connected":
            while not player.datetime.left and (datetime.now() - player.datetime.last_seen) < timedelta(seconds=10):
                if player.userip.usernames and player.iplookup.geolite2.is_initialized:
                    break
                gui_closed__event.wait(0.1)
            else:
                return

            from Modules.constants.standard import USERIP_DATABASES_PATH
            relative_database_path = player.userip.database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")

            with userip_logging_file_write_lock:
                write_lines_to_file(USERIP_LOGGING_PATH, "a", [(
                    f"User{pluralize(len(player.userip.usernames))}:{', '.join(player.userip.usernames)} | "
                    f"IP:{player.ip} | Ports:{', '.join(map(str, reversed(player.ports.list)))} | "
                    f"Time:{player.userip.detection.date_time} | Country:{player.iplookup.geolite2.country} | "
                    f"Detection Type: {player.userip.detection.type} | "
                    f"Database:{relative_database_path}"
                )])

            if player.userip.settings.NOTIFICATIONS:
                while not player.datetime.left and (datetime.now() - player.datetime.last_seen) < timedelta(seconds=10):
                    if player.iplookup.ipapi.is_initialized:
                        break
                    gui_closed__event.wait(0.1)
                else:
                    return

                msgbox_title = TITLE
                msgbox_message = textwrap.indent(textwrap.dedent(f"""
                    #### UserIP detected at {player.userip.detection.time} ####
                    User{pluralize(len(player.userip.usernames))}: {', '.join(player.userip.usernames)}
                    IP: {player.ip}
                    Port{pluralize(len(player.ports.list))}: {', '.join(map(str, reversed(player.ports.list)))}
                    Country Code: {player.iplookup.geolite2.country_code}
                    Detection Type: {player.userip.detection.type}
                    Database: {relative_database_path}
                    ############# IP Lookup ##############
                    Continent: {player.iplookup.ipapi.continent}
                    Country: {player.iplookup.geolite2.country}
                    Region: {player.iplookup.ipapi.region}
                    City: {player.iplookup.geolite2.city}
                    Organization: {player.iplookup.ipapi.org}
                    ISP: {player.iplookup.ipapi.isp}
                    ASN / ISP: {player.iplookup.geolite2.asn}
                    ASN: {player.iplookup.ipapi.as_name}
                    Mobile (cellular) connection: {player.iplookup.ipapi.mobile}
                    Proxy, VPN or Tor exit address: {player.iplookup.ipapi.proxy}
                    Hosting, colocated or data center: {player.iplookup.ipapi.hosting}
                """.removeprefix("\n").removesuffix("\n")), "    ")
                msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.SystemModal | MsgBox.Style.MsgBoxSetForeground
                threading.Thread(target=MsgBox.show, args=(msgbox_title, msgbox_message, msgbox_style), daemon=True).start()

def iplookup_core():
    with Threads_ExceptionHandler():
        def throttle_until(requests_remaining: int, throttle_time: int):
            # Calculate sleep time only if there are remaining requests
            sleep_time = throttle_time / requests_remaining if requests_remaining > 0 else throttle_time

            # We sleep x seconds (just in case) to avoid triggering a "429" status code.
            gui_closed__event.wait(sleep_time)

        # Following values taken from https://ip-api.com/docs/api:batch the 03/04/2024.
        MAX_REQUESTS = 15
        MAX_THROTTLE_TIME = 60
        MAX_BATCH_IP_API_IPS = 100
        FIELDS_TO_LOOKUP = "continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query"

        def validate_and_get_field(
            player_ip: str,
            data: dict[str, Any],
            field: str,
            expected_types: tuple[Type[Any], ...]
        ):
            """Retrieve a field from a dictionary and validate its type."""
            result = data.get(field, "N/A")

            if result != "N/A" and not isinstance(result, expected_types):
                expected_names = " or ".join(t.__name__ for t in expected_types)
                raise TypeError(f'Expected "{expected_names}" for "{field}", got "{type(result).__name__}" ({player_ip})')

            return result

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            ips_to_lookup: list[str] = []

            for player in PlayersRegistry.get_sorted_players():
                if player.iplookup.ipapi.is_initialized:
                    continue

                ips_to_lookup.append(player.ip)

                if len(ips_to_lookup) == MAX_BATCH_IP_API_IPS:
                    break

            if not ips_to_lookup:
                gui_closed__event.wait(1)
                continue

            try:
                response = s.post(
                    f"http://ip-api.com/batch?fields={FIELDS_TO_LOOKUP}",
                    headers={"Content-Type": "application/json"},
                    json=ips_to_lookup,
                    timeout=3
                )
                response.raise_for_status()
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                gui_closed__event.wait(1)
                continue
            except requests.exceptions.HTTPError as e:
                if isinstance(e.response, requests.Response) and e.response.status_code == 429:  # Handle rate limiting
                    throttle_until(int(e.response.headers["X-Rl"]), int(e.response.headers["X-Ttl"]))
                    continue
                raise  # Re-raise other HTTP errors

            iplookup_results: list[dict[str, Any]] = response.json()
            if not isinstance(iplookup_results, list):
                raise TypeError(f'Expected "list" object, got "{type(iplookup_results).__name__}"')

            for iplookup in iplookup_results:
                if not isinstance(iplookup, dict):
                    raise TypeError(f'Expected "dict" object, got "{type(iplookup).__name__}"')

                player_ip = iplookup.get("query")
                if not isinstance(player_ip, str):
                    raise TypeError(f'Expected "str" object, got "{type(player_ip).__name__}"')

                if player := PlayersRegistry.get_player(player_ip):
                    player.iplookup.ipapi.is_initialized = True

                    field_mappings: dict[str, tuple[str, tuple[Type[Any], ...]]] = {
                        "continent": ("continent", str),
                        "continent_code": ("continentCode", str),
                        "country": ("country", str),
                        "country_code": ("countryCode", str),
                        "region": ("regionName", str),
                        "region_code": ("region", str),
                        "city": ("city", str),
                        "district": ("district", str),
                        "zip_code": ("zip", str),
                        "lat": ("lat", (float, int)),
                        "lon": ("lon", (float, int)),
                        "time_zone": ("timezone", str),
                        "offset": ("offset", int),
                        "currency": ("currency", str),
                        "isp": ("isp", str),
                        "org": ("org", str),
                        "_as": ("as", str),
                        "as_name": ("asname", str),
                        "mobile": ("mobile", bool),
                        "proxy": ("proxy", bool),
                        "hosting": ("hosting", bool),
                    }

                    for attr, (field, field_type) in field_mappings.items():
                        setattr(player.iplookup.ipapi, attr, validate_and_get_field(player_ip, iplookup, field, field_type))

            throttle_until(int(response.headers["X-Rl"]), int(response.headers["X-Ttl"]))

def hostname_core():
    with Threads_ExceptionHandler():
        from concurrent.futures import ThreadPoolExecutor, Future
        from Modules.networking.reverse_dns_lookup import ReverseDNS

        reverse_dns = ReverseDNS()

        with ThreadPoolExecutor(max_workers=32) as executor:
            futures: dict[Future, str] = {}  # Maps futures to their corresponding IPs
            pending_ips: set[str] = set()   # Tracks IPs currently being processed

            while not gui_closed__event.is_set():
                if ScriptControl.has_crashed():
                    return

                for player in PlayersRegistry.get_sorted_players():
                    if player.reverse_dns.is_initialized or player.ip in pending_ips:
                        continue

                    future = executor.submit(reverse_dns.lookup, player.ip)
                    futures[future] = player.ip
                    pending_ips.add(player.ip)

                if not futures:
                    gui_closed__event.wait(1)
                    continue

                for future, ip in list(futures.items()):
                    if not future.done():
                        continue

                    futures.pop(future)

                    hostname: str = future.result()
                    if not isinstance(hostname, str):
                        raise TypeError(f'Expected "PingResult" object, got "{type(hostname).__name__}"')

                    if player := PlayersRegistry.get_player(ip):
                        player.reverse_dns.is_initialized = True

                        player.reverse_dns.hostname = hostname

                gui_closed__event.wait(0.1)

def pinger_core():
    with Threads_ExceptionHandler():
        from concurrent.futures import ThreadPoolExecutor, Future
        from Modules.networking.endpoint_ping_manager import AllEndpointsExhausted, PingResult, fetch_and_parse_ping

        with ThreadPoolExecutor(max_workers=32) as executor:
            futures: dict[Future, str] = {}  # Maps futures to their corresponding IPs
            pending_ips: set[str] = set()   # Tracks IPs currently being processed

            while not gui_closed__event.is_set():
                if ScriptControl.has_crashed():
                    return

                for player in PlayersRegistry.get_sorted_players():
                    if player.ping.is_initialized or player.ip in pending_ips:
                        continue

                    future = executor.submit(fetch_and_parse_ping, player.ip)
                    futures[future] = player.ip
                    pending_ips.add(player.ip)

                if not futures:
                    gui_closed__event.wait(1)
                    continue

                for future, ip in list(futures.items()):
                    if not future.done():
                        continue

                    futures.pop(future)
                    pending_ips.remove(ip)

                    try:
                        ping_result: Union[PingResult, None] = future.result()
                    except AllEndpointsExhausted:
                        continue

                    if ping_result is None:
                        continue

                    if not isinstance(ping_result, PingResult):
                        raise TypeError(f'Expected "PingResult" object, got "{type(ping_result).__name__}"')

                    if player := PlayersRegistry.get_player(ip):
                        player.ping.is_initialized = True
                        player.ping.is_pinging = ping_result.packets_received > 0

                        player.ping.ping_times = ping_result.ping_times
                        player.ping.packets_transmitted = ping_result.packets_transmitted
                        player.ping.packets_received = ping_result.packets_received
                        player.ping.packet_loss = ping_result.packet_loss
                        player.ping.packet_errors = ping_result.packet_errors
                        player.ping.rtt_min = ping_result.rtt_min
                        player.ping.rtt_avg = ping_result.rtt_avg
                        player.ping.rtt_max = ping_result.rtt_max
                        player.ping.rtt_mdev = ping_result.rtt_mdev

                gui_closed__event.wait(0.1)

def capture_core():
    with Threads_ExceptionHandler():
        def packet_callback(packet: Packet):
            global tshark_restarted_times, global_pps_counter

            packet_datetime = packet.frame.datetime

            packet_latency = datetime.now() - packet_datetime
            tshark_packets_latencies.append((packet_datetime, packet_latency))
            if packet_latency >= timedelta(seconds=Settings.CAPTURE_OVERFLOW_TIMER):
                tshark_restarted_times += 1
                raise PacketCaptureOverflow("Packet capture time exceeded 3 seconds.")

            if Settings.CAPTURE_IP_ADDRESS:
                if packet.ip.src == Settings.CAPTURE_IP_ADDRESS:
                    target_ip = packet.ip.dst
                    target_port = packet.udp.dstport
                elif packet.ip.dst == Settings.CAPTURE_IP_ADDRESS:
                    target_ip = packet.ip.src
                    target_port = packet.udp.srcport
                else:
                    return  # Neither source nor destination matches the specified `Settings.CAPTURE_IP_ADDRESS`.
            else:
                is_src_private_ip = is_private_device_ipv4(packet.ip.src)
                is_dst_private_ip = is_private_device_ipv4(packet.ip.dst)

                if is_src_private_ip and is_dst_private_ip:
                    return  # Both source and destination are private IPs, no action needed.
                elif is_src_private_ip:
                    target_ip = packet.ip.dst
                    target_port = packet.udp.dstport
                elif is_dst_private_ip:
                    target_ip = packet.ip.src
                    target_port = packet.udp.srcport
                else:
                    return  # Neither source nor destination is a private IP address.

            if target_port is None:
                return  # A packet port was not found.

            global_pps_counter += 1

            player = PlayersRegistry.get_player(target_ip)
            if player is None:
                player = PlayersRegistry.add_player(
                    Player(target_ip, target_port, packet_datetime)
                )

            if target_ip in UserIP_Databases.ips_set and not player.userip.detection.as_processed_userip_task:
                player.userip.detection.as_processed_userip_task = True
                player.userip.detection.type = "Static IP"
                player.userip.detection.time = packet_datetime.strftime("%H:%M:%S")
                player.userip.detection.date_time = packet_datetime.strftime("%Y-%m-%d_%H:%M:%S")
                if UserIP_Databases.update_player_userip_info(player):
                    threading.Thread(target=process_userip_task, args=(player, "connected"), daemon=True).start()

            if player.is_player_just_registered:
                player.is_player_just_registered = False
                return

            # No matter what:
            player.datetime.last_seen = packet_datetime
            player.total_packets += 1
            player.pps.counter += 1
            player.ppm.counter += 1

            if player.datetime.left: # player left, rejoined now.
                player.datetime.left = None
                player.datetime.last_rejoin = packet_datetime
                player.rejoins += 1
                player.packets = 1

                if Settings.GUI_RESET_PORTS_ON_REJOINS:
                    player.ports.reset(target_port)
                    return
            else:
                player.packets += 1

            # player connected, has not been reset
            if target_port not in player.ports.list:
                player.ports.list.append(target_port)
            player.ports.last = target_port

        while not gui_closed__event.is_set():
            try:
                capture.apply_on_packets(callback=packet_callback)
            except TSharkCrashException:
                if gui_closed__event.wait(3):
                    break
                raise
            except PacketCaptureOverflow:
                continue

tshark_packets_latencies: list[tuple[datetime, timedelta]] = []

class CellColor(NamedTuple):
    foreground: QColor
    background: QColor

class ThreadSafeMeta(type):
    """Metaclass that ensures thread-safe access to class attributes."""

    # Define a lock for the metaclass itself to be shared across all instances of classes using this metaclass.
    _lock = threading.Lock()

    def __getattr__(cls, name: str):
        """Thread-safe getter for attributes."""
        with cls._lock:
            if hasattr(cls, name):
                return getattr(cls, name)
            raise AttributeError(f"'{cls.__name__}' object has no attribute '{name}'")

    def __setattr__(cls, name: str, value):
        """Thread-safe setter for attributes."""
        with cls._lock:
            super().__setattr__(name, value)

class GUIrenderingData(metaclass=ThreadSafeMeta):
    FIELDS_TO_HIDE: list[str] = []
    GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES: list[str] = []
    GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES: list[str] = []

    header_text: str = ""
    SESSION_CONNECTED_TABLE__NUM_COLS: int = 0
    session_connected_table__num_rows: int = 0
    session_connected_table__processed_data: list[list[str]] = [[]]
    session_connected_table__compiled_colors: list[list[CellColor]] = [[]]
    SESSION_DISCONNECTED_TABLE__NUM_COLS: int = 0
    session_disconnected_table__num_rows: int = 0
    session_disconnected_table__processed_data: list[list[str]] = [[]]
    session_disconnected_table__compiled_colors: list[list[CellColor]] = [[]]

    session_connected_sorted_column_name: Optional[str] = None
    session_connected_sort_order: Optional[Qt.SortOrder] = None
    session_disconnected_sorted_column_name: Optional[str] = None
    session_disconnected_sort_order: Optional[Qt.SortOrder] = None

    gui_rendering_ready_event: threading.Event = threading.Event()

def rendering_core():
    with Threads_ExceptionHandler():
        def compile_tables_header_field_names():
            gui_connected_players_table__field_names = [
                field_name
                for field_name in Settings.gui_all_connected_fields
                if field_name not in GUIrenderingData.FIELDS_TO_HIDE
            ]
            gui_disconnected_players_table__field_names = [
                field_name
                for field_name in Settings.gui_all_disconnected_fields
                if field_name not in GUIrenderingData.FIELDS_TO_HIDE
            ]
            logging_connected_players_table__field_names = [
                field_name
                for field_name in Settings.gui_all_connected_fields
            ]
            logging_disconnected_players_table__field_names = [
                field_name
                for field_name in Settings.gui_all_disconnected_fields
            ]

            return (
                gui_connected_players_table__field_names,
                gui_disconnected_players_table__field_names,
                logging_connected_players_table__field_names,
                logging_disconnected_players_table__field_names
            )

        def sort_session_table(session_list: list[Player], sorted_column_name: str, sort_order: Qt.SortOrder) -> list[Player]:
            """
            Sorts a list of players based on the given column name and sort order.

            Args:
                session_list: The list of players to sort.
                sorted_column_name: The column name to sort by.
                sort_order: The sort order ("ascending" or "descending").

            Returns:
                The sorted list of players.
            """
            def sort_order_to_reverse(sort_order: Qt.SortOrder):
                """
                Converts a Qt.SortOrder to a reverse parameter for sorted().

                Args:
                    sort_order: The sort order from Qt (Ascending or Descending).
                """
                return sort_order == Qt.SortOrder.DescendingOrder

            def get_nested_attr(item, attr_path: str):
                """Retrieve a nested attribute from an object using a dot-separated path."""
                for attr in attr_path.split("."):
                    item = getattr(item, attr, None)
                    if item is None:
                        break
                return item

            if sorted_column_name == "Avg PPS":
                return sorted(
                    session_list,
                    key=lambda player: getattr(player.pps, "get_average")(),
                    reverse=sort_order_to_reverse(sort_order)
                )
            elif sorted_column_name == "Avg PPM":
                return sorted(
                    session_list,
                    key=lambda player: getattr(player.ppm, "get_average")(),
                    reverse=sort_order_to_reverse(sort_order)
                )
            elif sorted_column_name == "IP Address":
                import ipaddress

                return sorted(
                    session_list,
                    key=lambda player: ipaddress.ip_address(player.ip),
                    reverse=sort_order_to_reverse(sort_order)
                )
            elif sorted_column_name in ("First Seen", "Last Rejoin", "Last Seen"):
                return sorted(
                    session_list,
                    key=attrgetter(Settings.gui_fields_mapping[sorted_column_name]),
                    reverse=not sort_order_to_reverse(sort_order)
                )
            # Force sorting those fields as strings as they contain both bools AND strings.
            elif sorted_column_name in ("Mobile", "VPN", "Hosting", "Pinging"):
                return sorted(
                    session_list,
                    key=lambda item: str(get_nested_attr(item, Settings.gui_fields_mapping[sorted_column_name])).lower(),
                    reverse=not sort_order_to_reverse(sort_order)
                )
            else:
                # Handle sorting for other columns
                return sorted(
                    session_list,
                    key=attrgetter(Settings.gui_fields_mapping[sorted_column_name]),
                    reverse=sort_order_to_reverse(sort_order)
                )

        def parse_userip_ini_file(ini_path: Path, unresolved_ip_invalid: set[str]):
            from Modules.constants.standalone import USERIP_INI_SETTINGS_LIST
            from Modules.constants.standard import RE_SETTINGS_INI_PARSER_PATTERN, RE_USERIP_INI_PARSER_PATTERN

            def process_ini_line_output(line: str):
                return line.strip()

            if not ini_path.exists():
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(ini_path.absolute()))
            if not ini_path.is_file():
                raise InvalidFileError(str(ini_path.absolute()))

            settings: dict[str, Union[bool, str, int, float]] = {}
            userip: dict[str, list[str]] = {}
            current_section = None
            matched_settings: list[str] = []
            ini_data = ini_path.read_text("utf-8")
            corrected_ini_data_lines: list[str] = []

            for line in map(process_ini_line_output, ini_data.splitlines(keepends=True)):
                corrected_ini_data_lines.append(line)

                if line.startswith("[") and line.endswith("]"):
                    # we basically adding a newline if the previous line is not a newline for eyes visiblitly or idk how we say that
                    if corrected_ini_data_lines and len(corrected_ini_data_lines) > 1:
                        if not corrected_ini_data_lines[-2] == "":
                            corrected_ini_data_lines.insert(-1, "")  # Insert an empty string before the last line
                    current_section = line[1:-1]
                    continue

                if current_section is None:
                    continue

                elif current_section == "Settings":
                    match = RE_SETTINGS_INI_PARSER_PATTERN.search(line)
                    if not match:
                        # If it's a newline or a comment we don't really care about rewritting at this point.
                        if not line.startswith((";", "#")) or line == "":
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    setting = match.group("key")
                    if setting is None:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    if not isinstance(setting, str):
                        raise TypeError(f'Expected "str" object, got "{type(setting).__name__}"')
                    value = match.group("value")
                    if value is None:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    if not isinstance(value, str):
                        raise TypeError(f'Expected "str" object, got "{type(value).__name__}"')

                    setting = setting.strip()
                    if not setting:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    value = value.strip()
                    if not value:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    if not setting in USERIP_INI_SETTINGS_LIST:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    if setting in settings:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    else:
                        matched_settings.append(setting)
                        need_rewrite_current_setting = False
                        is_setting_corrupted = False

                        if setting == "ENABLED":
                            try:
                                settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                            except InvalidBooleanValueError:
                                is_setting_corrupted = True
                        elif setting == "COLOR":
                            if (q_color := QColor(value)).isValid():
                                settings[setting] = q_color
                            else:
                                is_setting_corrupted = True
                        elif setting == "LOG":
                            try:
                                settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                            except InvalidBooleanValueError:
                                is_setting_corrupted = True
                        elif setting == "NOTIFICATIONS":
                            try:
                                settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                            except InvalidBooleanValueError:
                                is_setting_corrupted = True
                        elif setting == "VOICE_NOTIFICATIONS":
                            try:
                                settings[setting], need_rewrite_current_setting = custom_str_to_bool(value, only_match_against=False)
                            except InvalidBooleanValueError:
                                case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ["Male", "Female"])
                                if case_insensitive_match:
                                    settings[setting] = normalized_match
                                    if not case_sensitive_match:
                                        need_rewrite_current_setting = True
                                else:
                                    is_setting_corrupted = True
                        elif setting == "PROTECTION":
                            try:
                                settings[setting], need_rewrite_current_setting = custom_str_to_bool(value, only_match_against=False)
                            except InvalidBooleanValueError:
                                case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ["Suspend_Process", "Exit_Process", "Restart_Process", "Shutdown_PC", "Restart_PC"])
                                if case_insensitive_match:
                                    settings[setting] = normalized_match
                                    if not case_sensitive_match:
                                        need_rewrite_current_setting = True
                                else:
                                    is_setting_corrupted = True
                        elif setting == "PROTECTION_PROCESS_PATH":
                            try:
                                settings[setting], need_rewrite_current_setting = custom_str_to_nonetype(value)
                            except InvalidNoneTypeValueError:
                                stripped_value = value.strip("\"'")
                                if not value == stripped_value:
                                    is_setting_corrupted = True
                                settings[setting] = Path(stripped_value.replace("\\", "/"))
                        elif setting == "PROTECTION_RESTART_PROCESS_PATH":
                            try:
                                settings[setting], need_rewrite_current_setting = custom_str_to_nonetype(value)
                            except InvalidNoneTypeValueError:
                                stripped_value = value.strip("\"'")
                                if not value == stripped_value:
                                    is_setting_corrupted = True
                                settings[setting] = Path(stripped_value.replace("\\", "/"))
                        elif setting == "PROTECTION_SUSPEND_PROCESS_MODE":
                                case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ["Auto", "Manual"])
                                if case_insensitive_match:
                                    settings[setting] = normalized_match
                                    if not case_sensitive_match:
                                        need_rewrite_current_setting = True
                                else:
                                    try:
                                        if "." in value:
                                            PROTECTION_SUSPEND_PROCESS_MODE = float(value)
                                        else:
                                            PROTECTION_SUSPEND_PROCESS_MODE = int(value)
                                    except (ValueError, TypeError):
                                        is_setting_corrupted = True
                                    else:
                                        if PROTECTION_SUSPEND_PROCESS_MODE >= 0:
                                            settings[setting] = PROTECTION_SUSPEND_PROCESS_MODE
                                        else:
                                            is_setting_corrupted = True

                        if is_setting_corrupted:
                            if not ini_path in UserIP_Databases.notified_settings_corrupted:
                                UserIP_Databases.notified_settings_corrupted.add(ini_path)
                                msgbox_title = TITLE
                                msgbox_message = textwrap.indent(textwrap.dedent(f"""
                                    ERROR:
                                        Corrupted UserIP Database File (Settings)

                                    INFOS:
                                        UserIP database file:
                                        \"{ini_path}\"
                                        has an invalid settings value:

                                        {setting}={value}

                                        For more information on formatting, please refer to the
                                        documentation:
                                        https://github.com/BUZZARDGTA/Session-Sniffer?tab=readme-ov-file#userip_ini_databases_tutorial
                                """.removeprefix("\n").removesuffix("\n")), "    ")
                                msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
                                threading.Thread(target=MsgBox.show, args=(msgbox_title, msgbox_message, msgbox_style), daemon=True).start()
                            return None, None

                        if need_rewrite_current_setting:
                            corrected_ini_data_lines[-1] = f"{setting}={settings[setting]}"

                elif current_section == "UserIP":
                    match = RE_USERIP_INI_PARSER_PATTERN.search(line)
                    if not match:
                        continue
                    username = match.group("username")
                    if username is None:
                        continue
                    if not isinstance(username, str):
                        raise TypeError(f'Expected "str" object, got "{type(username).__name__}"')
                    ip = match.group("ip")
                    if ip is None:
                        continue
                    if not isinstance(ip, str):
                        raise TypeError(f'Expected "str" object, got "{type(ip).__name__}"')

                    username = username.strip()
                    if not username:
                        continue
                    ip = ip.strip()
                    if not ip:
                        continue

                    if not is_ipv4_address(ip):
                        unresolved_ip_invalid.add(f"{ini_path}={username}={ip}")
                        if not f"{ini_path}={username}={ip}" in UserIP_Databases.notified_ip_invalid:
                            msgbox_title = TITLE
                            msgbox_message = textwrap.indent(textwrap.dedent(f"""
                                ERROR:
                                    UserIP databases invalid IP address

                                INFOS:
                                    The IP address from an entry is invalid (not an IP address).

                                DEBUG:
                                    \"{ini_path}\":
                                    {username}={ip}
                            """.removeprefix("\n").removesuffix("\n")), "    ")
                            msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.SystemModal | MsgBox.Style.MsgBoxSetForeground
                            threading.Thread(target=MsgBox.show, args=(msgbox_title, msgbox_message, msgbox_style), daemon=True).start()
                            UserIP_Databases.notified_ip_invalid.add(f"{ini_path}={username}={ip}")
                        continue

                    if username in userip:
                        if ip not in userip[username]:
                            userip[username].append(ip)
                    else:
                        userip[username] = [ip]

            list_of_missing_settings = [setting for setting in USERIP_INI_SETTINGS_LIST if setting not in matched_settings]
            number_of_settings_missing = len(list_of_missing_settings)

            if number_of_settings_missing > 0:
                if not ini_path in UserIP_Databases.notified_settings_corrupted:
                    UserIP_Databases.notified_settings_corrupted.add(ini_path)
                    msgbox_title = TITLE
                    msgbox_message = textwrap.indent(textwrap.dedent(f"""
                        ERROR:
                            Missing setting{pluralize(number_of_settings_missing)} in UserIP Database File

                        INFOS:
                            {number_of_settings_missing} missing setting{pluralize(number_of_settings_missing)} in UserIP database file:
                            \"{ini_path}\"

                            {"\n                ".join(f"<{setting.upper()}>" for setting in list_of_missing_settings)}

                            For more information on formatting, please refer to the
                            documentation:
                            https://github.com/BUZZARDGTA/Session-Sniffer?tab=readme-ov-file#userip_ini_databases_tutorial
                    """.removeprefix("\n").removesuffix("\n")), "    ")
                    msgbox_style = MsgBox.Style.OKOnly | MsgBox.Style.Exclamation | MsgBox.Style.MsgBoxSetForeground
                    threading.Thread(target=MsgBox.show, args=(msgbox_title, msgbox_message, msgbox_style), daemon=True).start()
                return None, None
            else:
                if ini_path in UserIP_Databases.notified_settings_corrupted:
                    UserIP_Databases.notified_settings_corrupted.remove(ini_path)

            # Basically always have a newline ending
            if len(corrected_ini_data_lines) > 1:
                if not corrected_ini_data_lines[-1] == "":
                    corrected_ini_data_lines.append("")

            fixed_ini_data = "\n".join(corrected_ini_data_lines)

            if not ini_data == fixed_ini_data:
                ini_path.write_text(fixed_ini_data, encoding="utf-8")

            return UserIP_Settings(
                settings["ENABLED"],
                settings["COLOR"],
                settings["LOG"],
                settings["NOTIFICATIONS"],
                settings["VOICE_NOTIFICATIONS"],
                settings["PROTECTION"],
                settings["PROTECTION_PROCESS_PATH"],
                settings["PROTECTION_RESTART_PROCESS_PATH"],
                settings["PROTECTION_SUSPEND_PROCESS_MODE"]
            ), userip

        def update_userip_databases(last_userip_parse_time: Optional[float]):
            from Modules.constants.standard import USERIP_DATABASES_PATH

            DEFAULT_USERIP_FILE_HEADER = textwrap.dedent(f"""
                ;;-----------------------------------------------------------------------------
                ;; {TITLE} User IP default database file
                ;;-----------------------------------------------------------------------------
                ;; Lines starting with \";\" or \"#\" symbols are commented lines.
                ;;
                ;; For detailed explanations of each setting, please refer to the following documentation:
                ;; https://github.com/BUZZARDGTA/Session-Sniffer/?tab=readme-ov-file#editing-settings
                ;;-----------------------------------------------------------------------------
                [Settings]
            """.removeprefix("\n").removesuffix("\n"))

            DEFAULT_USERIP_FILES_SETTINGS = {
                USERIP_DATABASES_PATH / "Blacklist.ini": """
                    ENABLED=True
                    COLOR=RED
                    LOG=True
                    NOTIFICATIONS=True
                    VOICE_NOTIFICATIONS=Male
                    PROTECTION=False
                    PROTECTION_PROCESS_PATH=None
                    PROTECTION_RESTART_PROCESS_PATH=None
                    PROTECTION_SUSPEND_PROCESS_MODE=Auto
                """,
                USERIP_DATABASES_PATH / "Enemylist.ini": """
                    ENABLED=True
                    COLOR=DARKGOLDENROD
                    LOG=True
                    NOTIFICATIONS=True
                    VOICE_NOTIFICATIONS=Male
                    PROTECTION=False
                    PROTECTION_PROCESS_PATH=None
                    PROTECTION_RESTART_PROCESS_PATH=None
                    PROTECTION_SUSPEND_PROCESS_MODE=Auto
                """,
                USERIP_DATABASES_PATH / "Friendlist.ini": """
                    ENABLED=True
                    COLOR=GREEN
                    LOG=True
                    NOTIFICATIONS=False
                    VOICE_NOTIFICATIONS=Female
                    PROTECTION=False
                    PROTECTION_PROCESS_PATH=None
                    PROTECTION_RESTART_PROCESS_PATH=None
                    PROTECTION_SUSPEND_PROCESS_MODE=Auto
                """,
                USERIP_DATABASES_PATH / "Randomlist.ini": """
                    ENABLED=True
                    COLOR=BLACK
                    LOG=True
                    NOTIFICATIONS=False
                    VOICE_NOTIFICATIONS=Female
                    PROTECTION=False
                    PROTECTION_PROCESS_PATH=None
                    PROTECTION_RESTART_PROCESS_PATH=None
                    PROTECTION_SUSPEND_PROCESS_MODE=Auto
                """,
                USERIP_DATABASES_PATH / "Searchlist.ini": """
                    ENABLED=True
                    COLOR=BLUE
                    LOG=True
                    NOTIFICATIONS=False
                    VOICE_NOTIFICATIONS=Female
                    PROTECTION=False
                    PROTECTION_PROCESS_PATH=None
                    PROTECTION_RESTART_PROCESS_PATH=None
                    PROTECTION_SUSPEND_PROCESS_MODE=Auto
                """
            }

            DEFAULT_USERIP_FILE_FOOTER = textwrap.dedent("""
                [UserIP]
                # Add users below in this format: username=IP
                # Examples:
                # username1=192.168.1.1
                # username2=127.0.0.1
                # username3=255.255.255.255
            """.removeprefix("\n"))

            USERIP_DATABASES_PATH.mkdir(parents=True, exist_ok=True)

            for userip_path, settings in DEFAULT_USERIP_FILES_SETTINGS.items():
                if not userip_path.is_file():
                    file_content = f"{DEFAULT_USERIP_FILE_HEADER}\n\n{settings}\n\n{DEFAULT_USERIP_FILE_FOOTER}"
                    userip_path.write_text(file_content, encoding="utf-8")

            # Remove deleted files from notified settings conflicts
            # TODO:
            # I should also warn again on another error, but it'd probably require a DICT then.
            # I have things more important to code atm.
            for file_path in set(UserIP_Databases.notified_settings_corrupted):
                if not file_path.is_file():
                    UserIP_Databases.notified_settings_corrupted.remove(file_path)

            new_databases: list[tuple[Path, UserIP_Settings, dict[str, list[str]]]] = []
            unresolved_ip_invalid: set[str] = set()

            for userip_path in USERIP_DATABASES_PATH.rglob("*.ini"):
                parsed_settings, parsed_data = parse_userip_ini_file(userip_path, unresolved_ip_invalid)
                if parsed_settings is None or parsed_data is None:
                    continue
                new_databases.append((userip_path, parsed_settings, parsed_data))

            UserIP_Databases.populate(new_databases)

            resolved_ip_invalids = UserIP_Databases.notified_ip_invalid - unresolved_ip_invalid
            for resolved_database_entry in resolved_ip_invalids:
                UserIP_Databases.notified_ip_invalid.remove(resolved_database_entry)

            UserIP_Databases.build()

            last_userip_parse_time = time.monotonic()
            return last_userip_parse_time

        def get_country_info(ip_address: str):
            country_name = "N/A"
            country_code = "N/A"

            if geoip2_enabled:
                try:
                    response = geolite2_country_reader.country(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    country_name = str(response.country.name)
                    country_code = str(response.country.iso_code)

            return country_name, country_code

        def get_city_info(ip_address: str):
            city = "N/A"

            if geoip2_enabled:
                try:
                    response = geolite2_city_reader.city(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    city = str(response.city.name)

            return city

        def get_asn_info(ip_address: str):
            asn = "N/A"

            if geoip2_enabled:
                try:
                    response = geolite2_asn_reader.asn(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    asn = str(response.autonomous_system_organization)

            return asn

        def get_minimum_padding(var: Union[str, float, int, bool], max_padding: int, padding: int):
            current_padding = len(str(var))

            if current_padding <= padding:
                if current_padding > max_padding:
                    max_padding = current_padding

            return max_padding

        def process_session_logging():
            def format_player_logging_datetime(datetime_object: datetime):
                return datetime_object.strftime('%m/%d/%Y %H:%M:%S.%f')[:-3]

            def format_player_logging_usernames(player_usernames: list[str]):
                return ", ".join(player_usernames) if player_usernames else "N/A"

            def format_player_logging_ip(player_ip: str):
                if SessionHost.player and SessionHost.player.ip == player_ip:
                    return f"{player_ip} 👑"
                return player_ip

            def format_player_logging_intermediate_ports(player_ports: Player_Ports):
                player_ports.intermediate = [port for port in reversed(player_ports.list) if port not in {player_ports.first, player_ports.last}]
                if player_ports.intermediate:
                    return ", ".join(map(str, player_ports.intermediate))
                else:
                    return ""

            def add_sort_arrow_char_to_sorted_logging_table_field(field_names: list[str], sorted_field: str, sort_order: Qt.SortOrder):
                arrow = " \u2193" if sort_order == Qt.SortOrder.DescendingOrder else " \u2191"  # Down arrow for descending, up arrow for ascending
                return [
                    field + arrow if field == sorted_field else field
                    for field in field_names
                ]

            # TODO:
            # When I have copilot again, ask it how can I manage to remove VSCode type hinting:
            # `(variable) session_connected_sorted_column_name: str | None` and `(variable) session_connected_sort_order: SortOrder | None`
            # `(variable) session_disconnected_sorted_column_name: str | None` and `(variable) session_disconnected_sort_order: SortOrder | None`
            # Specifically, at this point of the code they just cannot be None anymore, because we checked them to NOT be None earlier..
            logging_connected_players__field_names__with_down_arrow = add_sort_arrow_char_to_sorted_logging_table_field(LOGGING_CONNECTED_PLAYERS_TABLE__FIELD_NAMES, GUIrenderingData.session_connected_sorted_column_name, GUIrenderingData.session_connected_sort_order)
            logging_disconnected_players__field_names__with_down_arrow = add_sort_arrow_char_to_sorted_logging_table_field(LOGGING_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES, GUIrenderingData.session_disconnected_sorted_column_name, GUIrenderingData.session_disconnected_sort_order)

            logging_connected_players_table = PrettyTable()
            logging_connected_players_table.set_style(TableStyle.SINGLE_BORDER)
            logging_connected_players_table.title = f"Player{pluralize(len(session_connected_sorted))} connected in your session ({len(session_connected_sorted)}):"
            logging_connected_players_table.field_names = logging_connected_players__field_names__with_down_arrow
            logging_connected_players_table.align = "l"
            for player in session_connected_sorted:
                row_texts: list[str] = []
                row_texts.append(f"{format_player_logging_usernames(player.usernames)}")
                row_texts.append(f"{format_player_logging_datetime(player.datetime.first_seen)}")
                row_texts.append(f"{format_player_logging_datetime(player.datetime.last_rejoin)}")
                row_texts.append(f"{player.rejoins}")
                row_texts.append(f"{player.total_packets}")
                row_texts.append(f"{player.packets}")
                row_texts.append(f"{player.pps.rate}")
                row_texts.append(f"{player.pps.get_average()}")
                row_texts.append(f"{player.ppm.rate}")
                row_texts.append(f"{player.ppm.get_average()}")
                row_texts.append(f"{format_player_logging_ip(player.ip)}")
                row_texts.append(f"{player.reverse_dns.hostname}")
                row_texts.append(f"{player.ports.last}")
                row_texts.append(f"{format_player_logging_intermediate_ports(player.ports)}")
                row_texts.append(f"{player.ports.first}")
                row_texts.append(f"{player.iplookup.ipapi.continent:<{session_connected__padding_continent_name}} ({player.iplookup.ipapi.continent_code})")
                row_texts.append(f"{player.iplookup.geolite2.country:<{session_connected__padding_country_name}} ({player.iplookup.geolite2.country_code})")
                row_texts.append(f"{player.iplookup.ipapi.region}")
                row_texts.append(f"{player.iplookup.ipapi.region_code}")
                row_texts.append(f"{player.iplookup.geolite2.city}")
                row_texts.append(f"{player.iplookup.ipapi.district}")
                row_texts.append(f"{player.iplookup.ipapi.zip_code}")
                row_texts.append(f"{player.iplookup.ipapi.lat}")
                row_texts.append(f"{player.iplookup.ipapi.lon}")
                row_texts.append(f"{player.iplookup.ipapi.time_zone}")
                row_texts.append(f"{player.iplookup.ipapi.offset}")
                row_texts.append(f"{player.iplookup.ipapi.currency}")
                row_texts.append(f"{player.iplookup.ipapi.org}")
                row_texts.append(f"{player.iplookup.ipapi.isp}")
                row_texts.append(f"{player.iplookup.geolite2.asn}")
                row_texts.append(f"{player.iplookup.ipapi._as}")
                row_texts.append(f"{player.iplookup.ipapi.as_name}")
                row_texts.append(f"{player.iplookup.ipapi.mobile}")
                row_texts.append(f"{player.iplookup.ipapi.proxy}")
                row_texts.append(f"{player.iplookup.ipapi.hosting}")
                row_texts.append(f"{player.ping.is_pinging}")
                logging_connected_players_table.add_row(row_texts)

            logging_disconnected_players_table = PrettyTable()
            logging_disconnected_players_table.set_style(TableStyle.SINGLE_BORDER)
            logging_disconnected_players_table.title = f"Player{pluralize(len(session_disconnected_sorted))} who've left your session ({len(session_disconnected_sorted)}):"
            logging_disconnected_players_table.field_names = logging_disconnected_players__field_names__with_down_arrow
            logging_disconnected_players_table.align = "l"
            for player in session_disconnected_sorted:
                row_texts: list[str] = []
                row_texts.append(f"{format_player_logging_usernames(player.usernames)}")
                row_texts.append(f"{format_player_logging_datetime(player.datetime.first_seen)}")
                row_texts.append(f"{format_player_logging_datetime(player.datetime.last_rejoin)}")
                row_texts.append(f"{format_player_logging_datetime(player.datetime.last_seen)}")
                row_texts.append(f"{player.rejoins}")
                row_texts.append(f"{player.total_packets}")
                row_texts.append(f"{player.packets}")
                row_texts.append(f"{player.ip}")
                row_texts.append(f"{player.reverse_dns.hostname}")
                row_texts.append(f"{player.ports.last}")
                row_texts.append(f"{format_player_logging_intermediate_ports(player.ports)}")
                row_texts.append(f"{player.ports.first}")
                row_texts.append(f"{player.iplookup.ipapi.continent:<{session_disconnected__padding_continent_name}} ({player.iplookup.ipapi.continent_code})")
                row_texts.append(f"{player.iplookup.geolite2.country:<{session_disconnected__padding_country_name}} ({player.iplookup.geolite2.country_code})")
                row_texts.append(f"{player.iplookup.ipapi.region}")
                row_texts.append(f"{player.iplookup.ipapi.region_code}")
                row_texts.append(f"{player.iplookup.geolite2.city}")
                row_texts.append(f"{player.iplookup.ipapi.district}")
                row_texts.append(f"{player.iplookup.ipapi.zip_code}")
                row_texts.append(f"{player.iplookup.ipapi.lat}")
                row_texts.append(f"{player.iplookup.ipapi.lon}")
                row_texts.append(f"{player.iplookup.ipapi.time_zone}")
                row_texts.append(f"{player.iplookup.ipapi.offset}")
                row_texts.append(f"{player.iplookup.ipapi.currency}")
                row_texts.append(f"{player.iplookup.ipapi.org}")
                row_texts.append(f"{player.iplookup.ipapi.isp}")
                row_texts.append(f"{player.iplookup.geolite2.asn}")
                row_texts.append(f"{player.iplookup.ipapi._as}")
                row_texts.append(f"{player.iplookup.ipapi.as_name}")
                row_texts.append(f"{player.iplookup.ipapi.mobile}")
                row_texts.append(f"{player.iplookup.ipapi.proxy}")
                row_texts.append(f"{player.iplookup.ipapi.hosting}")
                row_texts.append(f"{player.ping.is_pinging}")
                logging_disconnected_players_table.add_row(row_texts)

            from Modules.constants.standard import SESSIONS_LOGGING_PATH

            # Check if the directories exist, if not create them
            if not SESSIONS_LOGGING_PATH.parent.is_dir():
                SESSIONS_LOGGING_PATH.parent.mkdir(parents=True)  # Create the directories if they don't exist

            # Check if the file exists, if not create it
            if not SESSIONS_LOGGING_PATH.is_file():
                SESSIONS_LOGGING_PATH.touch()  # Create the file if it doesn't exist

            SESSIONS_LOGGING_PATH.write_text(logging_connected_players_table.get_string() + "\n" + logging_disconnected_players_table.get_string(), encoding="utf-8")

        def process_gui_session_tables_rendering():
            def format_player_gui_datetime(datetime_object: datetime):
                formatted_elapsed = None

                if Settings.GUI_DATE_FIELDS_SHOW_ELAPSED:
                    elapsed_time = datetime.now() - datetime_object

                    hours, remainder = divmod(elapsed_time.total_seconds(), 3600)
                    minutes, remainder = divmod(remainder, 60)
                    seconds, milliseconds = divmod(remainder * 1000, 1000)

                    elapsed_parts: list[str] = []
                    if hours >= 1:
                        elapsed_parts.append(f"{int(hours):02}h")
                    if elapsed_parts or minutes >= 1:
                        elapsed_parts.append(f"{int(minutes):02}m")
                    if elapsed_parts or seconds >= 1:
                        elapsed_parts.append(f"{int(seconds):02}s")
                    if not elapsed_parts and milliseconds > 0:
                        elapsed_parts.append(f"{int(milliseconds):03}ms")

                    formatted_elapsed = " ".join(elapsed_parts)

                    if Settings.GUI_DATE_FIELDS_SHOW_DATE is False and Settings.GUI_DATE_FIELDS_SHOW_TIME is False:
                        return formatted_elapsed

                parts: list[str] = []
                if Settings.GUI_DATE_FIELDS_SHOW_DATE:
                    parts.append(datetime_object.strftime("%m/%d/%Y"))
                if Settings.GUI_DATE_FIELDS_SHOW_TIME:
                    parts.append(datetime_object.strftime("%H:%M:%S.%f")[:-3])
                if not parts:
                    raise ValueError("Invalid settings: Both date and time are disabled.")

                formatted_datetime = " ".join(parts)

                if formatted_elapsed:
                    formatted_datetime += f" ({formatted_elapsed})"

                return formatted_datetime

            def format_player_gui_usernames(player_usernames: list[str]):
                return ", ".join(player_usernames) if player_usernames else "N/A"

            def format_player_gui_ip(player_ip: str):
                if SessionHost.player and SessionHost.player.ip == player_ip:
                    return f"{player_ip} 👑"
                return player_ip

            def format_player_gui_intermediate_ports(player_ports: Player_Ports):
                player_ports.intermediate = [port for port in reversed(player_ports.list) if port not in {player_ports.first, player_ports.last}]
                if player_ports.intermediate:
                    return ", ".join(map(str, player_ports.intermediate))
                else:
                    return ""

            def get_player_gui_pps_color(pps_color: QColor, is_pps_first_calculation: bool, pps_rate: int):
                if not is_pps_first_calculation:
                    if pps_rate == 0:
                        pps_color = QColor("red")
                    elif pps_rate >= 1 and pps_rate <= 3:
                        pps_color = QColor("yellow")

                return pps_color

            def get_player_gui_avg_pps_color(avg_pps_color: QColor, is_pps_first_calculation: bool, pps_rate: int):
                if not is_pps_first_calculation:
                    if pps_rate == 0:
                        avg_pps_color = QColor("red")
                    elif pps_rate >= 1 and pps_rate <= 3:
                        avg_pps_color = QColor("yellow")

                return avg_pps_color

            def get_player_gui_ppm_color(ppm_color: QColor, is_ppm_first_calculation: bool, ppm_rate: int):
                if not is_ppm_first_calculation:
                    if ppm_rate == 0:
                        ppm_color = QColor("red")
                    elif ppm_rate >= 1 and ppm_rate <= 3:
                        ppm_color = QColor("yellow")

                return ppm_color

            def get_player_gui_avg_ppm_color(avg_ppm_color: QColor, is_ppm_first_calculation: bool, ppm_rate: int):
                if not is_ppm_first_calculation:
                    if ppm_rate == 0:
                        avg_ppm_color = QColor("red")
                    elif ppm_rate >= 1 and ppm_rate <= 3:
                        avg_ppm_color = QColor("yellow")

                return avg_ppm_color


            from Modules.constants.external import HARDCODED_DEFAULT_TABLE_BACKGROUD_CELL_COLOR

            session_connected_table__processed_data: list[list[str]] = []
            session_connected_table__compiled_colors: list[list[CellColor]] = []
            session_disconnected_table__processed_data: list[list[str]] = []
            session_disconnected_table__compiled_colors: list[list[CellColor]] = []

            for player in session_connected_sorted:
                if player.userip.usernames:
                    row_fg_color = QColor("white")
                    row_bg_color = player.userip.settings.COLOR
                else:
                    row_fg_color = QColor("lime")
                    row_bg_color = HARDCODED_DEFAULT_TABLE_BACKGROUD_CELL_COLOR

                # Initialize a list for cell colors for the current row, creating a new CellColor object for each column
                row_colors = [
                    CellColor(foreground=row_fg_color, background=row_bg_color)
                    for _ in range(GUIrenderingData.SESSION_CONNECTED_TABLE__NUM_COLS)
                ]

                row_texts: list[str] = []
                row_texts.append(f"{format_player_gui_usernames(player.usernames)}")
                row_texts.append(f"{format_player_gui_datetime(player.datetime.first_seen)}")
                row_texts.append(f"{format_player_gui_datetime(player.datetime.last_rejoin)}")
                row_texts.append(f"{player.rejoins}")
                row_texts.append(f"{player.total_packets}")
                row_texts.append(f"{player.packets}")
                if "PPS" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_colors[CONNECTED_COLUMN_MAPPING["PPS"]] = row_colors[CONNECTED_COLUMN_MAPPING["PPS"]]._replace(foreground=get_player_gui_pps_color(row_fg_color, player.pps.is_first_calculation, player.pps.rate)) # Update the foreground color for the "PPS" column
                    row_texts.append(f"{player.pps.rate}")
                if "Avg PPS" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_colors[CONNECTED_COLUMN_MAPPING["Avg PPS"]] = row_colors[CONNECTED_COLUMN_MAPPING["Avg PPS"]]._replace(foreground=get_player_gui_avg_pps_color(row_fg_color, player.pps.is_first_calculation, player.pps.rate)) # Update the foreground color for the "Avg PPS" column
                    row_texts.append(f"{player.pps.get_average()}")
                if "PPM" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_colors[CONNECTED_COLUMN_MAPPING["PPM"]] = row_colors[CONNECTED_COLUMN_MAPPING["PPM"]]._replace(foreground=get_player_gui_ppm_color(row_fg_color, player.ppm.is_first_calculation, player.ppm.rate)) # Update the foreground color for the "PPM" column
                    row_texts.append(f"{player.ppm.rate}")
                if "Avg PPM" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_colors[CONNECTED_COLUMN_MAPPING["Avg PPM"]] = row_colors[CONNECTED_COLUMN_MAPPING["Avg PPM"]]._replace(foreground=get_player_gui_avg_ppm_color(row_fg_color, player.ppm.is_first_calculation, player.ppm.rate)) # Update the foreground color for the "Avg PPM" column
                    row_texts.append(f"{player.ppm.get_average()}")
                row_texts.append(f"{format_player_gui_ip(player.ip)}")
                if "Hostname" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.reverse_dns.hostname}")
                if "Last Port" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.ports.last}")
                if "Intermediate Ports" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{format_player_gui_intermediate_ports(player.ports)}")
                if "First Port" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.ports.first}")
                if "Continent" not in GUIrenderingData.FIELDS_TO_HIDE:
                    if Settings.GUI_FIELD_SHOW_CONTINENT_CODE:
                        row_texts.append(f"{player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})")
                    else:
                        row_texts.append(f"{player.iplookup.ipapi.continent}")
                if "Country" not in GUIrenderingData.FIELDS_TO_HIDE:
                    if Settings.GUI_FIELD_SHOW_COUNTRY_CODE:
                        row_texts.append(f"{player.iplookup.geolite2.country} ({player.iplookup.geolite2.country_code})")
                    else:
                        row_texts.append(f"{player.iplookup.geolite2.country}")
                if "Region" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.region}")
                if "R. Code" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.region_code}")
                if "City" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.geolite2.city}")
                if "District" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.district}")
                if "ZIP Code" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.zip_code}")
                if "Lat" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.lat}")
                if "Lon" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.lon}")
                if "Time Zone" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.time_zone}")
                if "Offset" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.offset}")
                if "Currency" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.currency}")
                if "Organization" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.org}")
                if "ISP" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.isp}")
                if "ASN / ISP" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.geolite2.asn}")
                if "AS" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi._as}")
                if "ASN" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.as_name}")
                if "Mobile" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.mobile}")
                if "VPN" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.proxy}")
                if "Hosting" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.hosting}")
                if "Pinging" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.ping.is_pinging}")

                session_connected_table__processed_data.append(row_texts)
                session_connected_table__compiled_colors.append(row_colors)

            for player in session_disconnected_sorted:
                if player.userip.usernames:
                    row_fg_color = QColor("white")
                    row_bg_color = player.userip.settings.COLOR
                else:
                    row_fg_color = QColor("red")
                    row_bg_color = HARDCODED_DEFAULT_TABLE_BACKGROUD_CELL_COLOR

                # Initialize a list for cell colors for the current row, creating a new CellColor object for each column
                row_colors = [CellColor(foreground=row_fg_color, background=row_bg_color) for _ in range(GUIrenderingData.SESSION_DISCONNECTED_TABLE__NUM_COLS)]

                row_texts: list[str] = []
                row_texts.append(f"{format_player_gui_usernames(player.usernames)}")
                row_texts.append(f"{format_player_gui_datetime(player.datetime.first_seen)}")
                row_texts.append(f"{format_player_gui_datetime(player.datetime.last_rejoin)}")
                row_texts.append(f"{format_player_gui_datetime(player.datetime.last_seen)}")
                row_texts.append(f"{player.rejoins}")
                row_texts.append(f"{player.total_packets}")
                row_texts.append(f"{player.packets}")
                row_texts.append(f"{player.ip}")
                if "Hostname" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.reverse_dns.hostname}")
                if "Last Port" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.ports.last}")
                if "Intermediate Ports" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{format_player_gui_intermediate_ports(player.ports)}")
                if "First Port" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.ports.first}")
                if "Continent" not in GUIrenderingData.FIELDS_TO_HIDE:
                    if Settings.GUI_FIELD_SHOW_CONTINENT_CODE:
                        row_texts.append(f"{player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})")
                    else:
                        row_texts.append(f"{player.iplookup.ipapi.continent}")
                if "Country" not in GUIrenderingData.FIELDS_TO_HIDE:
                    if Settings.GUI_FIELD_SHOW_COUNTRY_CODE:
                        row_texts.append(f"{player.iplookup.geolite2.country} ({player.iplookup.geolite2.country_code})")
                    else:
                        row_texts.append(f"{player.iplookup.geolite2.country}")
                if "Region" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.region}")
                if "R. Code" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.region_code}")
                if "City" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.geolite2.city}")
                if "District" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.district}")
                if "ZIP Code" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.zip_code}")
                if "Lat" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.lat}")
                if "Lon" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.lon}")
                if "Time Zone" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.time_zone}")
                if "Offset" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.offset}")
                if "Currency" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.currency}")
                if "Organization" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.org}")
                if "ISP" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.isp}")
                if "ASN / ISP" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.geolite2.asn}")
                if "AS" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi._as}")
                if "ASN" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.as_name}")
                if "Mobile" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.mobile}")
                if "VPN" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.proxy}")
                if "Hosting" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.iplookup.ipapi.hosting}")
                if "Pinging" not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f"{player.ping.is_pinging}")

                session_disconnected_table__processed_data.append(row_texts)
                session_disconnected_table__compiled_colors.append(row_colors)

            return (
                len(session_connected_table__processed_data),
                session_connected_table__processed_data,
                session_connected_table__compiled_colors,
                len(session_disconnected_table__processed_data),
                session_disconnected_table__processed_data,
                session_disconnected_table__compiled_colors
            )

        def generate_gui_header_text(global_pps_last_update_time: float, global_pps_rate: int):
            global global_pps_counter, tshark_packets_latencies

            if capture.extracted_tshark_version == TSHARK_RECOMMENDED_VERSION_NUMBER:
                tshark_version_color = '<span style="color: green;">'
            else:
                tshark_version_color = '<span style="color: yellow;">'

            one_second_ago = datetime.now() - timedelta(seconds=1)

            # Filter packets received in the last second
            recent_packets = [(pkt_time, pkt_latency) for pkt_time, pkt_latency in tshark_packets_latencies if pkt_time >= one_second_ago]

            # Update latencies list to only keep recent packets
            tshark_packets_latencies[:] = recent_packets

            # Calculate average latency
            if recent_packets:
                total_latency_seconds = sum(pkt_latency.total_seconds() for _, pkt_latency in recent_packets)
                avg_latency_seconds = total_latency_seconds / len(recent_packets)
                avg_latency_rounded = round(avg_latency_seconds, 1)
            else:
                avg_latency_seconds = 0.0
                avg_latency_rounded = 0.0

            # Determine latency color
            if avg_latency_seconds >= 0.90 * Settings.CAPTURE_OVERFLOW_TIMER:
                latency_color = '<span style="color: red;">'
            elif avg_latency_seconds >= 0.75 * Settings.CAPTURE_OVERFLOW_TIMER:
                latency_color = '<span style="color: yellow;">'
            else:
                latency_color = '<span style="color: green;">'

            if (time.monotonic() - global_pps_last_update_time) >= 1.0:
                global_pps_rate = global_pps_counter
                global_pps_counter = 0
                global_pps_last_update_time = time.monotonic()

            # For reference, in a GTA Online session, the packets per second (PPS) typically range from 0 (solo session) to 1500 (public session, 32 players).
            # If the packet rate exceeds these ranges, we flag them with yellow or red color to indicate potential issues (such as scanning unwanted packets outside of the GTA game).
            # Also these values averagely indicates the max performances my script can run at during my testings. Luckely it's just enough to process GTA V game.
            if global_pps_rate >= 3000:
                pps_color = '<span style="color: red;">'
            elif global_pps_rate >= 1500:
                pps_color = '<span style="color: yellow;">'
            else:
                pps_color = '<span style="color: green;">'

            # NOTE: Hack for stupid VSCode type hinting
            if user_interface_selection is None:
                raise TypeError(f'Expected "int", got "NoneType"')

            is_vpn_mode_enabled = "Enabled" if Settings.CAPTURE_VPN_MODE or force_enable_capture_vpn_mode else "Disabled"
            is_arp_enabled = "Enabled" if interfaces_selection_data[user_interface_selection].is_arp else "Disabled"
            displayed_capture_ip_address = Settings.CAPTURE_IP_ADDRESS if Settings.CAPTURE_IP_ADDRESS else "N/A"
            color_tshark_restarted_time = '<span style="color: green;">' if tshark_restarted_times == 0 else '<span style="color: red;">'
            if Settings.DISCORD_PRESENCE:
                rpc_message = f' RPC:<span style="color: green;">Connected</span>' if discord_rpc_manager.connection_status.is_set() else f' RPC:<span style="color: yellow;">Waiting for Discord</span>'
            else:
                rpc_message = ""

            num_of_userip_files = len(UserIP_Databases.get_userip_database_filepaths())
            invalid_ip_count = len(UserIP_Databases.notified_ip_invalid)
            conflict_ip_count = len(UserIP_Databases.notified_ip_conflicts)
            corrupted_settings_count = len(UserIP_Databases.notified_settings_corrupted)

            header = f"""
            <div style="background: linear-gradient(90deg, #2e3440, #4c566a); color: white; padding: 20px; border: 2px solid #88c0d0; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.3);">
                <div>
                    <span style="font-size: 24px; color: #88c0d0">Welcome to {TITLE}</span>&nbsp;&nbsp;<span style="font-size: 14px; color: #aaa">{VERSION}</span>
                </div>
                <p style="font-size: 16px; margin: 5px 0;">
                    The best FREE and Open-Source packet sniffer, aka IP grabber, works WITHOUT mods.
                </p>
                <p style="font-size: 14px; margin: 5px 0;">
                    Scanning with TShark {tshark_version_color}v{capture.extracted_tshark_version}</span> on Interface <span style="color: yellow;">{capture.interface}</span> | IP:<span style="color: yellow;">{displayed_capture_ip_address}</span> | ARP:<span style="color: yellow;">{is_arp_enabled}</span> | VPN:<span style="color: yellow;">{is_vpn_mode_enabled}</span>
                </p>
                <p style="font-size: 14px; margin: 5px 0;">
                    Packets latency per sec:{latency_color}{avg_latency_rounded}</span>/<span style="color: green;">{Settings.CAPTURE_OVERFLOW_TIMER}</span> (tshark restart{pluralize(tshark_restarted_times)}:{color_tshark_restarted_time}{tshark_restarted_times}</span>) PPS:{pps_color}{global_pps_rate}</span>{rpc_message}
                </p>
            </div>
            """

            if any([invalid_ip_count, conflict_ip_count, corrupted_settings_count]):
                header += "───────────────────────────────────────────────────────────────────────────────────────────────────<br>"
                if invalid_ip_count:
                    header += f"Number of invalid IP{pluralize(invalid_ip_count)} in UserIP file{pluralize(num_of_userip_files)}: <span style=\"color: red;\">{invalid_ip_count}</span><br>"
                if conflict_ip_count:
                    header += f"Number of conflicting IP{pluralize(conflict_ip_count)} in UserIP file{pluralize(num_of_userip_files)}: <span style=\"color: red;\">{conflict_ip_count}</span><br>"
                if corrupted_settings_count:
                    header += f"Number of corrupted setting(s) in UserIP file{pluralize(num_of_userip_files)}: <span style=\"color: red;\">{corrupted_settings_count}</span><br>"
                header += "───────────────────────────────────────────────────────────────────────────────────────────────────"
            return header, global_pps_last_update_time, global_pps_rate

        from Modules.constants.standard import TWO_TAKE_ONE__PLUGIN__LOG_PATH, STAND__PLUGIN__LOG_PATH, RE_MODMENU_LOGS_USER_PATTERN
        from Modules.constants.local import CHERAX__PLUGIN__LOG_PATH

        GUIrenderingData.FIELDS_TO_HIDE = set(Settings.GUI_FIELDS_TO_HIDE)
        (
            GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES,
            GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES,
            LOGGING_CONNECTED_PLAYERS_TABLE__FIELD_NAMES,
            LOGGING_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES
        ) = compile_tables_header_field_names()

        GUIrenderingData.SESSION_CONNECTED_TABLE__NUM_COLS = len(GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES)
        GUIrenderingData.SESSION_DISCONNECTED_TABLE__NUM_COLS = len(GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES)
        # Define the column name to index mapping for connected and disconnected players
        CONNECTED_COLUMN_MAPPING = {header: index for index, header in enumerate(GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES)}
        #DISCONNECTED_COLUMN_MAPPING = {header: index for index, header in enumerate(GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES)}

        global_pps_last_update_time = time.monotonic()
        global_pps_rate = 0
        last_userip_parse_time = None
        last_mod_menus_logs_parse_time = None
        last_session_logging_processing_time = None

        if Settings.DISCORD_PRESENCE:
            from Modules.discord.rpc import DiscordRPC
            from Modules.constants.standalone import DISCORD_APPLICATION_ID

            discord_rpc_manager = DiscordRPC(client_id=DISCORD_APPLICATION_ID)

        modmenu__plugins__ip_to_usernames: dict[str, list[str]] = {}

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            # Wait for sorting fields to be initialized from the GUI
            while GUIrenderingData.session_connected_sorted_column_name is None or \
                GUIrenderingData.session_disconnected_sorted_column_name is None or \
                GUIrenderingData.session_disconnected_sort_order is None or \
                GUIrenderingData.session_connected_sort_order is None:
                gui_closed__event.wait(0.1)
                continue

            session_connected: list[Player] = []
            session_disconnected: list[Player] = []

            if last_mod_menus_logs_parse_time is None or time.monotonic() - last_mod_menus_logs_parse_time >= 1.0:
                last_mod_menus_logs_parse_time = time.monotonic()

                for log_path in (STAND__PLUGIN__LOG_PATH, CHERAX__PLUGIN__LOG_PATH, TWO_TAKE_ONE__PLUGIN__LOG_PATH):
                    if not log_path.is_file():
                        continue

                    # Read the content and split it into lines
                    for line in log_path.read_text(encoding="utf-8").splitlines():
                        match = RE_MODMENU_LOGS_USER_PATTERN.match(line)
                        if not match:
                            continue

                        username = match.group("username")
                        if not isinstance(username, str):
                            continue

                        ip = match.group("ip")
                        if not isinstance(ip, str):
                            continue

                        if ip not in modmenu__plugins__ip_to_usernames:
                            modmenu__plugins__ip_to_usernames[ip] = []
                        if not username in modmenu__plugins__ip_to_usernames[ip]:
                            modmenu__plugins__ip_to_usernames[ip].append(username)

            if last_userip_parse_time is None or time.monotonic() - last_userip_parse_time >= 1.0:
                last_userip_parse_time = update_userip_databases(last_userip_parse_time)

            if Settings.GUI_SESSIONS_LOGGING:
                session_connected__padding_country_name = 0
                session_connected__padding_continent_name = 0
                session_disconnected__padding_country_name = 0
                session_disconnected__padding_continent_name = 0

            for player in PlayersRegistry.get_sorted_players():
                if player.ip in UserIP_Databases.ips_set:
                    UserIP_Databases.update_player_userip_info(player)
                else:
                    player.userip.reset()

                if modmenu__plugins__ip_to_usernames and player.ip in modmenu__plugins__ip_to_usernames:
                    for username in modmenu__plugins__ip_to_usernames[player.ip]:
                        if username not in player.mod_menus.usernames:
                            player.mod_menus.usernames.append(username)

                player.usernames = concat_lists_no_duplicates(player.mod_menus.usernames, player.userip.usernames)

                if (
                    not player.datetime.left
                    and (datetime.now() - player.datetime.last_seen).total_seconds() >= Settings.GUI_DISCONNECTED_PLAYERS_TIMER
                ):
                    player.datetime.left = player.datetime.last_seen
                    if player.userip.detection.time:
                        player.userip.detection.as_processed_userip_task = False
                        threading.Thread(target=process_userip_task, args=(player, "disconnected"), daemon=True).start()

                if not player.iplookup.geolite2.is_initialized:
                    player.iplookup.geolite2.country, player.iplookup.geolite2.country_code = get_country_info(player.ip)
                    player.iplookup.geolite2.city = get_city_info(player.ip)
                    player.iplookup.geolite2.asn = get_asn_info(player.ip)

                    player.iplookup.geolite2.is_initialized = True

                if player.datetime.left:
                    session_disconnected.append(player)

                    if Settings.GUI_SESSIONS_LOGGING:
                        session_disconnected__padding_country_name = get_minimum_padding(player.iplookup.geolite2.country, session_disconnected__padding_country_name, 27)
                        session_disconnected__padding_continent_name = get_minimum_padding(player.iplookup.ipapi.continent, session_disconnected__padding_continent_name, 13)
                else:
                    session_connected.append(player)

                    if Settings.GUI_SESSIONS_LOGGING:
                        session_connected__padding_country_name = get_minimum_padding(player.iplookup.geolite2.country, session_connected__padding_country_name, 27)
                        session_connected__padding_continent_name = get_minimum_padding(player.iplookup.ipapi.continent, session_connected__padding_continent_name, 13)

                    # Calculate PPS every second
                    if (time.monotonic() - player.pps.last_update_time) >= 1.0:
                        player.pps.rate = player.pps.counter  # Count of packets in the last second
                        player.pps.update_average(player.pps.rate)
                        player.pps.counter = 0
                        player.pps.last_update_time = time.monotonic()
                        player.pps.is_first_calculation = False

                    # Calculate PPM every minute
                    if (time.monotonic() - player.ppm.last_update_time) >= 60.0:
                        player.ppm.rate = player.ppm.counter  # Count of packets in the last minute
                        player.ppm.update_average(player.ppm.rate)
                        player.ppm.counter = 0
                        player.ppm.last_update_time = time.monotonic()
                        player.ppm.is_first_calculation = False

            if Settings.CAPTURE_PROGRAM_PRESET == "GTA5":
                if SessionHost.player:
                    if SessionHost.player.datetime.left:
                        SessionHost.player = None
                # TODO: We should also potentially needs to check that not more then 1s passed before each disconnected
                if SessionHost.players_pending_for_disconnection and all(player.datetime.left for player in SessionHost.players_pending_for_disconnection):
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection.clear()

                if len(session_connected) == 0:
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection.clear()
                elif len(session_connected) >= 1 and all(not player.pps.is_first_calculation and player.pps.rate == 0 for player in session_connected):
                    SessionHost.players_pending_for_disconnection = session_connected
                else:
                    if SessionHost.search_player:
                        SessionHost.get_host_player(session_connected)

            session_connected_sorted = sort_session_table(
                session_connected,
                GUIrenderingData.session_connected_sorted_column_name,
                GUIrenderingData.session_connected_sort_order
            )
            session_disconnected_sorted = sort_session_table(
                session_disconnected,
                GUIrenderingData.session_disconnected_sorted_column_name,
                GUIrenderingData.session_disconnected_sort_order
            )

            if Settings.GUI_SESSIONS_LOGGING and (last_session_logging_processing_time is None or (time.monotonic() - last_session_logging_processing_time) >= 1.0):
                process_session_logging()
                last_session_logging_processing_time = time.monotonic()

            if Settings.DISCORD_PRESENCE and (discord_rpc_manager.last_update_time is None or (time.monotonic() - discord_rpc_manager.last_update_time) >= 3.0):
                discord_rpc_manager.update(f"{len(session_connected_sorted)} player{pluralize(len(session_connected_sorted))} connected")

            GUIrenderingData.header_text, global_pps_last_update_time, global_pps_rate = generate_gui_header_text(global_pps_last_update_time, global_pps_rate)
            (
                GUIrenderingData.session_connected_table__num_rows,
                GUIrenderingData.session_connected_table__processed_data,
                GUIrenderingData.session_connected_table__compiled_colors,
                GUIrenderingData.session_disconnected_table__num_rows,
                GUIrenderingData.session_disconnected_table__processed_data,
                GUIrenderingData.session_disconnected_table__compiled_colors
            ) = process_gui_session_tables_rendering()
            GUIrenderingData.gui_rendering_ready_event.set()

            gui_closed__event.wait(1)

cls()
title(f"DEBUG CONSOLE - {TITLE}")

tshark_restarted_times = 0
global_pps_counter = 0

PlayersRegistry.start_cache_updater()

rendering_core__thread = threading.Thread(target=rendering_core, daemon=True)
rendering_core__thread.start()

hostname_core__thread = threading.Thread(target=hostname_core, daemon=True)
hostname_core__thread.start()

iplookup_core__thread = threading.Thread(target=iplookup_core, daemon=True)
iplookup_core__thread.start()

pinger_core__thread = threading.Thread(target=pinger_core, daemon=True)
pinger_core__thread.start()

capture_core__thread = threading.Thread(target=capture_core, daemon=True)
capture_core__thread.start()

class SessionTableModel(QAbstractTableModel):
    def __init__(self, headers: list[str], sort_column: int, sort_order: Qt.SortOrder):
        super().__init__()
        self._headers = headers  # The column headers
        self._data: list[list[str]] = []  # The data to be displayed in the table

        # Custom Variables
        self._view: Optional[SessionTableView] = None  # Initially, no view is attached
        self._compiled_colors: list[list[CellColor]] = []  # The compiled colors for the table
        self._IP_COLUMN_INDEX = self._headers.index("IP Address")

    def rowCount(self, parent=None):
        return len(self._data)  # The number of rows in the model

    def columnCount(self, parent=None):
        return len(self._headers)  # The number of columns in the model

    def data(self, index, role: int):
        """Override data method to customize data retrieval and alignment."""
        if not index.isValid():
            return None

        row_idx = index.row()
        col_idx = index.column()

        # Check bounds
        if row_idx >= len(self._data) or col_idx >= len(self._data[row_idx]):
            return None  # Return None for invalid index

        if role == Qt.ItemDataRole.DisplayRole:
            # Return the cell's text
            return self._data[row_idx][col_idx]

        if role == Qt.ItemDataRole.ForegroundRole:
            # Return the cell's foreground color
            if row_idx < len(self._compiled_colors) and col_idx < len(self._compiled_colors[row_idx]):
                return QBrush(self._compiled_colors[row_idx][col_idx].foreground)

        if role == Qt.ItemDataRole.BackgroundRole:
            # Return the cell's background color
            if row_idx < len(self._compiled_colors) and col_idx < len(self._compiled_colors[row_idx]):
                return QBrush(self._compiled_colors[row_idx][col_idx].background)

        if role == Qt.ItemDataRole.ToolTipRole:
            # Ensure the view is attached
            if self._view is None:
                return None

            # Get the column resize mode
            header = self._view.horizontalHeader()
            if not isinstance(header, QHeaderView):
                raise TypeError(f'Expected "QHeaderView", got "{type(header).__name__}"')
            resize_mode = header.sectionResizeMode(index.column())

            # Return None if the column resize mode isn't set to Stretch, as it shouldn't be truncated
            if resize_mode != QHeaderView.ResizeMode.Stretch:
                return None

            cell_text = self._data[row_idx][col_idx]

            font_metrics = self._view.fontMetrics()
            text_width = font_metrics.horizontalAdvance(cell_text)
            column_width = self._view.columnWidth(index.column())

            TEXT_TRUNCATION_MARGIN = 8
            if text_width > column_width - TEXT_TRUNCATION_MARGIN:
                return cell_text

        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal:
            if role == Qt.ItemDataRole.DisplayRole:
                return self._headers[section]  # Display the header name
            elif role == Qt.ItemDataRole.ToolTipRole:
                from Modules.constants.standalone import GUI_COLUMN_HEADERS_TOOLTIP_MAPPING
                # Fetch the header name and return the corresponding tooltip
                header_name = self._headers[section]
                return GUI_COLUMN_HEADERS_TOOLTIP_MAPPING.get(header_name, None)

        return None

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid():
            return False

        if role == Qt.ItemDataRole.EditRole:
            self._data[index.row()][index.column()] = value  # Set the data at the specified index
            self.dataChanged.emit(index, index, [Qt.ItemDataRole.DisplayRole])  # Notify the view of data change
            return True

        return False

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def sort(self, column, order):
        """
        Sort the table by a specific column.

        Args:
            column: The column index to sort by.
            order: The order (ascending/descending) to sort in.
        """
        if not self._data:
            if self._compiled_colors:
                raise ValueError("Inconsistent state: It's not possible to have colors if there's no data.")
            return  # No data to process, exit early.

        if not self._compiled_colors:
            raise ValueError("Inconsistent state: It's not possible to have data without colors.")

        self.layoutAboutToBeChanged.emit()

        sorted_column_name = self._headers[column]
        # Combine data and colors for sorting
        combined = list(zip(self._data, self._compiled_colors))
        if not combined:
            raise ValueError("Inconsistent state: 'combined' is unexpectedly empty at this point.")
        sort_order_bool = order == Qt.SortOrder.DescendingOrder

        if sorted_column_name == "IP Address":
            import ipaddress

            # Sort by IP address
            combined.sort(
                key=lambda row: ipaddress.ip_address(row[0][column].removesuffix(" 👑")),
                reverse=sort_order_bool
            )
        elif sorted_column_name in ("First Seen", "Last Rejoin", "Last Seen"):
            # Retrieve the player datetime object from the IP column
            def extract_datetime_for_ip(ip: str):
                """
                Extracts a datetime object for a given IP address.
                """
                player = PlayersRegistry.get_player(ip)
                if not isinstance(player, Player):
                    raise TypeError(f'Expected "Player", got "{type(player).__name__}"')

                # Retrieve the player datetime attribute name for the selected column
                # Mapping column names to player datetime attributes
                datetime_attribute = {
                    "First Seen": "first_seen",
                    "Last Rejoin": "last_rejoin",
                    "Last Seen": "last_seen"
                }.get(self._headers[column], None)
                if not isinstance(datetime_attribute, str):
                    raise TypeError(f'Expected "str", got "{type(datetime_attribute).__name__}"')

                # Safely retrieve the attribute using `getattr`
                return getattr(player.datetime, datetime_attribute)

            combined.sort(
                key=lambda row: extract_datetime_for_ip(row[0][self._IP_COLUMN_INDEX].removesuffix(" 👑")),
                reverse=not sort_order_bool
            )
        else:
            # Sort by other columns: numerically if the strings represent numbers, otherwise case-insensitively
            combined.sort(
                key=lambda row: (
                    float(row[0][column]) if row[0][column].replace('.', '', 1).isdigit() else row[0][column].lower()
                ),
                reverse=sort_order_bool
            )

        # Unpack the sorted data
        self._data, self._compiled_colors = zip(*combined)
        self._data, self._compiled_colors = list(self._data), list(self._compiled_colors)

        self.layoutChanged.emit()

    # Custom Methods:

    def set_view(self, view: "SessionTableView"):
        self._view = view

    def get_column_index(self, column_name: str):
        """
        Get the table index of a specified column.

        Args:
            column_name: The column name to look for.

        Returns:
            The table column index.
        """
        column_index = self._headers.index(column_name)

        return column_index

    def get_row_index_by_ip(self, ip_address: str):
        """
        Finds the row index for the given IP address.

        Args:
            ip_address: The IP address to search for.

        Returns:
            The index of the row containing the IP address, or None if not found.
        """
        for row_index, row_data in enumerate(self._data):
            if row_data[self._IP_COLUMN_INDEX].removesuffix(" 👑") == ip_address:
                return row_index
        return None

    def sort_current_column(self):
        """
        Calls the sort method with the current column index and order.
        Ensures sorting reflects the current state of the header.
        """
        if not self._view:
            return

        # Retrieve the current sort column and order
        header = self._view.horizontalHeader()
        if not isinstance(header, QHeaderView):
            raise TypeError(f'Expected "QHeaderView", got "{type(header).__name__}"')
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()

        # Call the sort function with the retrieved arguments
        self.sort(sort_column, sort_order)

    def add_row_without_refresh(self, row_data: list[str], row_colors: list[CellColor]):
        """
        Adds a new row to the model without notifying the view in real time.

        Args:
            row_data: The data for the new row.
            row_colors: A list of `CellColor` objects corresponding to the row's colors.
        """
        # Only update internal data without triggering signals
        self._data.append(row_data)
        self._compiled_colors.append(row_colors)

    def update_row_without_refresh(self, row_index: int, row_data: list[str], row_colors: list[CellColor]):
        """
        Updates an existing row in the model with new data and colors without notifying the view in real time.

        Args:
            row_index: The index of the row to update.
            row_data: The new data for the row.
            row_colors: A list of `CellColor` objects corresponding to the row's colors.
        """
        if 0 <= row_index < self.rowCount():
            self._data[row_index] = row_data
            self._compiled_colors[row_index] = row_colors

    def delete_row(self, row_index: int):
        """
        Deletes a row from the model along with its associated colors.
        If any items are selected under this row, their selection moves one row up.

        Args:
            row_index: The index of the row to delete.
        """
        if 0 <= row_index < self.rowCount():
            # Access the selection model from the view if it's available
            if self._view:
                selection_model = self._view.selectionModel()
                if not isinstance(selection_model, QItemSelectionModel):
                    raise TypeError(f'Expected "QItemSelectionModel", got "{type(selection_model).__name__}"')

            # Adjust selection for the deleted row
            for index in selection_model.selection().indexes():
                if index.row() == row_index:  # Row to be deleted
                    # Deselect the row because it's about to be deleted
                    # Select the row to be deleted
                    selection = QItemSelection(
                        self.index(index.row(), index.column()),
                        self.index(index.row(), index.column())
                    )
                    selection_model.select(selection, QItemSelectionModel.SelectionFlag.Deselect)

            # Notify the view that rows are about to be removed
            self.beginRemoveRows(self.index(row_index, 0), row_index, row_index)

            # Remove the data and compiled colors at the specified index
            self._data.pop(row_index)
            self._compiled_colors.pop(row_index)

            # Adjust selection for rows below the deleted one
            for index in selection_model.selection().indexes():
                if index.row() > row_index:  # Items below the deleted row
                    # Deselect the original row
                    selection_to_deselect = QItemSelection(
                        self.index(index.row(), index.column()),  # Original row
                        self.index(index.row(), index.column())
                    )
                    selection_model.select(selection_to_deselect, QItemSelectionModel.SelectionFlag.Deselect)

                    # Move the selection up by one row
                    selection_to_select = QItemSelection(
                        self.index(index.row() - 1, index.column()),  # New row after deletion
                        self.index(index.row() - 1, index.column())
                    )
                    selection_model.select(selection_to_select, QItemSelectionModel.SelectionFlag.Select)

            # Notify the view that the rows have been removed
            self.endRemoveRows()

            # NOTE: Fixes a weird UI bug that when someone leaves, it makes it an empty row
            if not self._data:
                # Begin resetting the model to indicate it's empty
                self.beginResetModel()
                self._data = []
                self._compiled_colors = []
                # End reset and notify the view that the model has been reset
                self.endResetModel()

            ## Ensure the view resizes properly after a row is removed
            #if self._view:
            #    self._view.resizeRowsToContents()
            #    self._view.viewport().update()

    def refresh_view(self):
        """
        Notifies the view to refresh and reflect all changes made to the model.
        """
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()

class SessionTableView(QTableView):
    def __init__(self, model: SessionTableModel, sort_column: int, sort_order: Qt.SortOrder):
        super().__init__()
        self.setModel(model)
        self._is_dragging = False  # Track if the mouse is being dragged with Ctrl key
        self._previous_sort_section_index: Optional[int] = None

        # Configure table view settings
        self.verticalHeader().setVisible(False)  # Hide row index
        self.setAlternatingRowColors(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.horizontalHeader().setSectionsClickable(True)
        self.horizontalHeader().sectionClicked.connect(self.on_section_clicked)
        self.horizontalHeader().setSectionsMovable(True)
        self.setSelectionMode(QTableView.SelectionMode.NoSelection)
        self.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)
        self.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)

        # Set the sort indicator for the specified column
        self.setSortingEnabled(False)
        self.horizontalHeader().setSortIndicator(sort_column, sort_order)
        self.horizontalHeader().setSortIndicatorShown(True)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def keyPressEvent(self, event):
        """
        Handle key press events to capture Ctrl+A for selecting all and Ctrl+C for copying selected data to the clipboard.
        Fall back to default behavior for other key presses.
        """
        if isinstance(event, QKeyEvent):
            # Check for Ctrl+C key combination and copy selection
            if event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                if event.key() == Qt.Key.Key_A:
                    self.select_all_cells()
                elif event.key() == Qt.Key.Key_C:
                    selected_model = self.model()
                    if not isinstance(selected_model, SessionTableModel):
                        raise TypeError(f'Expected "SessionTableModel", got "{type(selected_model).__name__}"')

                    selection_model = self.selectionModel()
                    if not isinstance(selection_model, QItemSelectionModel):
                        raise TypeError(f'Expected "QItemSelectionModel", got "{type(selection_model).__name__}"')

                    selected_indexes = selection_model.selectedIndexes()

                    self.copy_selected_cells(selected_model, selected_indexes)
                return

        # Fall back to default behavior
        super().keyPressEvent(event)

    def mousePressEvent(self, event):
        """
        Handle mouse press events for selecting multiple items with Ctrl or single items otherwise.
        Fall back to default behavior for non-cell areas.
        """
        if isinstance(event, QMouseEvent):
            # Determine the index of the clicked item
            index = self.indexAt(event.pos())

            # Check if the index is valid
            if index.isValid():
                selection_model = self.selectionModel()
                if not isinstance(selection_model, QItemSelectionModel):
                    raise TypeError(f'Expected "QItemSelectionModel", got "{type(selection_model).__name__}"')

                if event.button() == Qt.MouseButton.RightButton:
                    if not selection_model.isSelected(index):
                        selection_model.select(index, QItemSelectionModel.SelectionFlag.ClearAndSelect)
                        return

                elif event.button() == Qt.MouseButton.LeftButton:
                    # Determine selection flag based on modifier keys
                    if event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                        # Toggle selection while keeping other selections
                        selection_flag = (
                            QItemSelectionModel.SelectionFlag.Deselect
                            if selection_model.isSelected(index)
                            else QItemSelectionModel.SelectionFlag.Select
                        )
                        self._is_dragging = True  # Start tracking dragging
                    elif event.modifiers() == Qt.KeyboardModifier.NoModifier:
                        was_selection_index_selected = selection_model.isSelected(index)

                        # Clear existing selections
                        selection_model.clearSelection()

                        # Select or Deselect the clicked cell
                        selection_flag = (
                            QItemSelectionModel.SelectionFlag.Deselect
                            if was_selection_index_selected
                            else QItemSelectionModel.SelectionFlag.Select
                        )

                    # Apply the determined selection flag
                    selection_model.select(index, selection_flag)
                    return

        # Fall back to default behavior
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        """
        Handle mouse move events for selecting multiple items while holding the Ctrl key.
        """
        if isinstance(event, QMouseEvent):
            if self._is_dragging and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                # Get the index under the cursor
                index = self.indexAt(event.pos())

                if index.isValid():
                    selection_model = self.selectionModel()
                    if not isinstance(selection_model, QItemSelectionModel):
                        raise TypeError(f'Expected "QItemSelectionModel", got "{type(selection_model).__name__}"')

                    # Select the current cell
                    selection_model.select(index, QItemSelectionModel.SelectionFlag.Select)
                    return

        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        """
        Reset dragging state when the mouse button is released.
        """
        self._is_dragging = False
        super().mouseReleaseEvent(event)

    def handleMenuHovered(self, action):
        # Fixes: https://stackoverflow.com/questions/21725119/why-wont-qtooltips-appear-on-qactions-within-a-qmenu
        if isinstance(action, QAction):
            action_parent = action.parent()
            if isinstance(action_parent, QMenu):
                action_parent.setToolTip(action.toolTip())

    # Custom Methods:

    def adjust_table_column_widths(self):
        """Adjust the column widths of a QTableView to fit content."""
        model = self.model()
        if not isinstance(model, SessionTableModel):
            raise TypeError(f'Expected "SessionTableModel", got "{type(model).__name__}"')

        header = self.horizontalHeader()
        if not isinstance(header, QHeaderView):
            raise TypeError(f'Expected "QHeaderView", got "{type(header).__name__}"')

        for column in range(model.columnCount()):
            # Get the header label for the column
            header_label = model.headerData(column, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)

            if header_label == "Usernames":
                # Check if the column contains any data other than "N/A"
                contains_non_na = any(
                    model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole) != "N/A"
                    for row in range(model.rowCount())
                )

                if contains_non_na:
                    header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
                else:
                    header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
            elif header_label in ("First Seen", "Last Rejoin", "Last Seen", "Rejoins", "T. Packets", "Packets", "PPS", "Avg PPS", "PPM", "Avg PPM", "IP Address", "First Port", "Last Port", "Mobile", "VPN", "Hosting", "Pinging"):
                header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
            else:
                header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)

    def get_sorted_column(self):
        """Get the currently sorted column and its order for this table view."""
        model = self.model()
        if not isinstance(model, SessionTableModel):
            raise TypeError(f'Expected "SessionTableModel", got "{type(model).__name__}"')

        header = self.horizontalHeader()
        if header is None:
            raise TypeError(f'Expected "QHeaderView", got "{type(header).__name__}"')

        # Get the index of the currently sorted column
        sorted_column_index = header.sortIndicatorSection()

        # Get the sort order (ascending or descending)
        sort_order = header.sortIndicatorOrder()

        # Get the name of the sorted column from the model
        sorted_column_name = model.headerData(
            sorted_column_index, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole
        )
        if not isinstance(sorted_column_name, str):
            raise TypeError(f'Expected "str", got "{type(sorted_column_name).__name__}"')

        return sorted_column_name, sort_order

    def on_section_clicked(self, section_index: int):
        model = self.model()
        if not isinstance(model, SessionTableModel):
            raise TypeError(f'Expected "SessionTableModel", got "{type(model).__name__}"')

        header = self.horizontalHeader()
        if not isinstance(header, QHeaderView):
            raise TypeError(f'Expected "QHeaderView", got "{type(header).__name__}"')

        # Clear selections when a header section is clicked
        # TODO: We can uses the "IP Address" field to store previous selections and their indexes and apply them back after sorting.
        self.selectionModel().clearSelection()

        # If it's the first click or sorting is being toggled
        if self._previous_sort_section_index is None or self._previous_sort_section_index != section_index:
            # TODO: If it's a string column, sort in AscendingOrder
            header.setSortIndicator(section_index, Qt.SortOrder.DescendingOrder)

        # Sort the model
        model.sort(section_index, header.sortIndicatorOrder())
        self._previous_sort_section_index = section_index

    def show_context_menu(self, pos: QPoint):
        """
        Show the context menu at the specified position with options to interact with the table's content.
        """
        from Modules.constants.standard import CUSTOM_CONTEXT_MENU_STYLESHEET, USERIP_DATABASES_PATH

        def add_action(menu: QMenu, label: str, shortcut: Optional[str] = None, tooltip: Optional[str] = None, handler = None, enabled: Optional[bool] = None):
            """Helper to create and configure a QAction."""
            action = menu.addAction(label)
            if action is None:
                raise TypeError(f'Expected "QAction", got "None"')

            if shortcut:
                action.setShortcut(shortcut)
            if tooltip:
                action.setToolTip(tooltip)
            if enabled is False:
                action.setEnabled(enabled)
            else:
                if handler:
                    action.triggered.connect(handler)

            return action

        def add_menu(parent_menu: QMenu, label: str, tooltip: Optional[str] = None):
            """Helper to create and configure a QMenu."""
            menu = parent_menu.addMenu(label)
            if menu is None:
                raise TypeError(f'Expected "QMenu", got "None"')

            if tooltip:
                menu.setToolTip(tooltip)

            return menu

        # Determine the index at the clicked position
        index = self.indexAt(pos)
        if not index.isValid():
            return  # Do nothing if the click is outside valid cells

        selected_model = self.model()
        if not isinstance(selected_model, SessionTableModel):
            raise TypeError(f'Expected "SessionTableModel", got "{type(selected_model).__name__}"')

        selection_model = self.selectionModel()
        if not isinstance(selection_model, QItemSelectionModel):
            raise TypeError(f'Expected "QItemSelectionModel", got "{type(selection_model).__name__}"')

        selected_indexes = selection_model.selectedIndexes()

        # Create the main context menu
        context_menu = QMenu(self)
        context_menu.setStyleSheet(CUSTOM_CONTEXT_MENU_STYLESHEET)
        context_menu.setToolTipsVisible(True)
        context_menu.hovered.connect(self.handleMenuHovered)

        # Add "Copy Selection" action
        add_action(
            context_menu,
            "Copy Selection",
            shortcut="Ctrl+C",
            tooltip="Copy selected cells to your clipboard.",
            handler=lambda: self.copy_selected_cells(selected_model, selected_indexes),
        )
        context_menu.addSeparator()

        # "Select" submenu
        select_menu = add_menu(context_menu, "Select  ")
        add_action(
            select_menu,
            "Select All",
            shortcut="Ctrl+A",
            tooltip="Select all cells in the table.",
            handler=self.select_all_cells,
        )
        add_action(
            select_menu,
            "Select Row",
            tooltip="Select all cells in this row.",
            handler=lambda: self.select_row_cells(index.row()),
        )
        add_action(
            select_menu,
            "Select Column",
            tooltip="Select all cells in this column.",
            handler=lambda: self.select_column_cells(index.column()),
        )

        # "Unselect" submenu
        unselect_menu = add_menu(context_menu, "Unselect")
        add_action(
            unselect_menu,
            "Unselect All",
            tooltip="Unselect all cells in the table.",
            handler=lambda: self.select_all_cells(unselect=True),
        )
        add_action(
            unselect_menu,
            "Unselect Row",
            tooltip="Unselect all cells in this row.",
            handler=lambda: self.select_row_cells(index.row(), unselect=True),
        )
        add_action(
            unselect_menu,
            "Unselect Column",
            tooltip="Unselect all cells in this column.",
            handler=lambda: self.select_column_cells(index.column(), unselect=True),
        )
        context_menu.addSeparator()

        # Process if one cell is selected
        if len(selected_indexes) == 1:
            selected_column = selected_indexes[0].column()

            column_name = selected_model.headerData(selected_column, Qt.Orientation.Horizontal)
            if not isinstance(column_name, str):
                raise TypeError(f'Expected "str", got "{type(column_name).__name__}"')

            if column_name == "IP Address":
                # Get the IP address from the selected cell
                ip_address = selected_model.data(selected_indexes[0], Qt.ItemDataRole.DisplayRole)
                if not isinstance(ip_address, str):
                    return  # Added this return cuz some rare times it would raise.
                    # raise TypeError(f'Expected "str", got "{type(ip_address).__name__}"')
                ip_address = ip_address.removesuffix(" 👑")

                userip_database_filepaths = UserIP_Databases.get_userip_database_filepaths()

                add_action(
                    context_menu,
                    "IP Lookup Details",
                    tooltip="Displays a notification with a detailed IP lookup report for selected player.",
                    handler=lambda: self.show_detailed_ip_lookup_player_cell(ip_address),
                )

                ping_menu = add_menu(context_menu, "Ping    ")
                add_action(
                    ping_menu,
                    "Normal",
                    tooltip="Checks if selected IP address responds to pings.",
                    handler=lambda: self.ping(ip_address),
                )
                add_action(
                    ping_menu,
                    "Spoofed (check-host.net API)",
                    tooltip="Checks if selected IP address responds to pings from 'check-host.net'.\n\nNOTE: This only works if Python is installed on your system.",
                    handler=lambda: self.ping_spoofed(ip_address),
                )
                add_action(
                    ping_menu,
                    "TCP Port (paping.exe)",
                    tooltip="Checks if selected IP address responds to TCP pings on a given port.",
                    handler=lambda: self.tcp_port_ping(ip_address),
                )

                userip_menu = add_menu(context_menu, "UserIP  ")

                if ip_address not in UserIP_Databases.ips_set:
                    add_userip_menu = add_menu(userip_menu, "Add     ", "Add selected IP address to UserIP database.") # Extra spaces for alignment
                    for database_path in userip_database_filepaths:
                        add_action(
                            add_userip_menu,
                            str(database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")),
                            tooltip=f'Add selected IP address to this UserIP database.',
                            handler=lambda _, database_path=database_path: self.userip_manager__add([ip_address], database_path),
                        )
                else:
                    userip_info = UserIP_Databases.get_userip_info(ip_address)
                    if userip_info is None:
                        raise TypeError(f'Expected "UserIP", got "None"')

                    # TODO:
                    #add_action(
                    #    userip_menu,
                    #    "Rename  ", # Extra spaces for alignment
                    #    tooltip="Rename this IP address from UserIP databases.",
                    #    handler=lambda: self.userip_manager__rename([ip_address]),
                    #)
                    move_userip_menu = add_menu(userip_menu, "Move    ", "Move selected IP address to another database.")
                    for database_path in userip_database_filepaths:
                        add_action(
                            move_userip_menu,
                            str(database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")),
                            tooltip=f'Move selected IP address to this UserIP database.',
                            handler=lambda _, database_path=database_path: self.userip_manager__move([ip_address], database_path),
                            enabled=userip_info.database_path != database_path,
                        )
                    add_action(
                        userip_menu,
                        "Delete  ", # Extra spaces for alignment
                        tooltip="Delete selected IP address from UserIP databases.",
                        handler=lambda: self.userip_manager__del([ip_address]),
                    )
        else:
            # Check if all selected cells are in the "IP Address" column
            if all(
                selected_model.headerData(index.column(), Qt.Orientation.Horizontal) == "IP Address"
                for index in selected_indexes
            ):
                all_ip_addresses: list[str] = []

                # Get the IP addreses from the selected cells
                for index in selected_indexes:
                    ip_address = selected_model.data(index, Qt.ItemDataRole.DisplayRole)
                    if not isinstance(ip_address, str):
                        raise TypeError(f'Expected "str", got "{type(ip_address).__name__}"')
                    ip_address = ip_address.removesuffix(" 👑")
                    all_ip_addresses.append(ip_address)

                if all(ip not in UserIP_Databases.ips_set for ip in all_ip_addresses):
                    userip_menu = add_menu(context_menu, "UserIP  ")
                    add_userip_menu = add_menu(userip_menu, "Add Selected")
                    for database_path in UserIP_Databases.get_userip_database_filepaths():
                        add_action(
                            add_userip_menu,
                            str(database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")),
                            tooltip=f'Add selected IP addresses to this UserIP database.',
                            handler=lambda _, database_path=database_path: self.userip_manager__add(all_ip_addresses, database_path),
                        )
                elif all(ip in UserIP_Databases.ips_set for ip in all_ip_addresses):
                    userip_menu = add_menu(context_menu, "UserIP  ")

                    # TODO:
                    #add_action(
                    #    userip_menu,
                    #    "Rename Selected", # Extra spaces for alignment
                    #    tooltip="Rename these IP addresses from UserIP databases.",
                    #    handler=lambda: self.userip_manager__rename([ip_address]),
                    #)

                    move_userip_menu = add_menu(userip_menu, "Move Selected")
                    for database_path in UserIP_Databases.get_userip_database_filepaths():
                        add_action(
                            move_userip_menu,
                            str(database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")),
                            tooltip=f'Move selected IP addresses to this UserIP database.',
                            handler=lambda _, database_path=database_path: self.userip_manager__move(all_ip_addresses, database_path),
                        )
                    add_action(
                        userip_menu,
                        "Delete Selected", # Extra spaces for alignment
                        tooltip="Delete selected IP addresses from UserIP databases.",
                        handler=lambda: self.userip_manager__del(all_ip_addresses),
                    )

        # Execute the context menu at the right-click position
        context_menu.exec(self.mapToGlobal(pos))

    def copy_selected_cells(self, selected_model: SessionTableModel, selected_indexes: Optional[list[QModelIndex]] = None):
        """
        Copy the selected cells data from the table to the clipboard.
        """
        # Access the system clipboard
        clipboard = QApplication.clipboard()
        if not isinstance(clipboard, QClipboard):
            raise TypeError(f'Expected "QClipboard", got "{type(clipboard).__name__}"')

        # Prepare a list to store text data from selected cells
        selected_texts: list[str] = []

        # Iterate over each selected index and retrieve its display data
        for index in selected_indexes:
            cell_text = selected_model.data(index, Qt.ItemDataRole.DisplayRole)
            if not isinstance(cell_text, str):
                raise TypeError(f'Expected "str", got "{type(cell_text).__name__}"')
            selected_texts.append(cell_text)

        # Return if no text was selected
        if not selected_texts:
            return

        # Join all selected text entries with a newline to format for copying
        clipboard_content = "\n".join(selected_texts)

        # Set the formatted text in the system clipboard
        clipboard.setText(clipboard_content)

    def show_detailed_ip_lookup_player_cell(self, ip_address: str):
        player = PlayersRegistry.get_player(ip_address)
        if not isinstance(player, Player):
            raise TypeError(f'Expected "Player", got "{type(player).__name__}"')

        from Modules.constants.standard import USERIP_DATABASES_PATH

        msgbox_message = textwrap.dedent(f"""
            ############ Player Infos #############
            IP Address: {player.ip}
            Hostname: {player.reverse_dns.hostname}
            Username{pluralize(len(player.usernames))}: {', '.join(player.usernames) or "N/A"}
            In UserIP database: {player.userip.database_path and f"{player.userip.database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")}" or "No"}
            Last Port: {player.ports.last}
            Intermediate Port{pluralize(len(player.ports.intermediate))}: {', '.join(map(str, player.ports.intermediate))}
            First Port: {player.ports.first}

            ########## IP Lookup Details ##########
            Continent: {player.iplookup.ipapi.continent}
            Country: {player.iplookup.geolite2.country}
            Country Code: {player.iplookup.geolite2.country_code}
            Region: {player.iplookup.ipapi.region}
            Region Code: {player.iplookup.ipapi.region_code}
            City: {player.iplookup.geolite2.city}
            District: {player.iplookup.ipapi.district}
            ZIP Code: {player.iplookup.ipapi.zip_code}
            Lat: {player.iplookup.ipapi.lat}
            Lon: {player.iplookup.ipapi.lon}
            Time Zone: {player.iplookup.ipapi.time_zone}
            Offset: {player.iplookup.ipapi.offset}
            Currency: {player.iplookup.ipapi.currency}
            Organization: {player.iplookup.ipapi.org}
            ISP: {player.iplookup.ipapi.isp}
            ASN / ISP: {player.iplookup.geolite2.asn}
            AS: {player.iplookup.ipapi._as}
            ASN: {player.iplookup.ipapi.as_name}
            Mobile (cellular) connection: {player.iplookup.ipapi.mobile}
            Proxy, VPN or Tor exit address: {player.iplookup.ipapi.proxy}
            Hosting, colocated or data center: {player.iplookup.ipapi.hosting}

            ############ Ping Response ############
            Ping Times: {player.ping.ping_times}
            Packets Transmitted: {player.ping.packets_transmitted}
            Packets Received: {player.ping.packets_received}
            Packet Loss: {player.ping.packet_loss}
            Packet Errors: {player.ping.packet_errors}
            Round-Trip Time Minimum: {player.ping.rtt_min}
            Round-Trip Time Average: {player.ping.rtt_avg}
            Round-Trip Time Maximum: {player.ping.rtt_max}
            Round-Trip Time Mean Deviation: {player.ping.rtt_mdev}
        """).removeprefix("\n").removesuffix("\n")
        QMessageBox.information(self, TITLE, msgbox_message)

    def ping(self, ip: str):
        """ Runs a continuous ping to a specified IP address in a new terminal window. """

        try:
            subprocess.Popen(
                ["cmd.exe", "/K", "ping", ip, "-t"],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to start ping:\n{e}")

    def ping_spoofed(self, ip: str):
        """ Runs a continuous ping to a specified IP address in a new terminal window. """
        from Modules.constants.local import SCRIPTS_PATH

        try:
            subprocess.Popen(
                ["cmd.exe", "/K", "py", SCRIPTS_PATH / "spoofed_ping.py", ip],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to start ping (spoofed):\n{e}")

    def tcp_port_ping(self, ip: str):
        """ Runs paping to check TCP connectivity to a host on a user-specified port indefinitely. """

        def run_paping(host: str, port: int):
            """ Runs paping in a new terminal window to check TCP connectivity continuously. """
            from Modules.constants.local import BIN_PATH

            try:
                subprocess.Popen(
                    ["cmd.exe", "/K", BIN_PATH / 'paping.exe', host, "-p", str(port)],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to start paping:\n{e}")

        port, ok = QInputDialog.getText(self, "Input Port", "Enter the port number to check TCP connectivity:")

        if not ok:
            return

        if not port.isdigit():
            QMessageBox.warning(self, "Error", "No valid port number provided.")
            return

        port = int(port)

        if not 1 <= port <= 65535:
            QMessageBox.warning(self, "Error", "Please enter a valid port number between 1 and 65535.")
            return

        run_paping(ip, port)

    # TODO:
    #def userip_manager__rename(self, ip_addresses: list[str]):
    #    # Prompt the user for the new username
    #    new_username, ok = QInputDialog.getText(self, "Input New Username", F"Please enter the new username to associate with the selected IP{pluralize(len(ip_addresses))}:")
    #
    #    if ok and new_username:
    #        # TODO:
    #        pass

    def userip_manager__add(self, ip_addresses: list[str], selected_database: Path):
        from Modules.constants.standard import USERIP_DATABASES_PATH

        # Prompt the user for a username
        username, ok = QInputDialog.getText(self, "Input Username", f"Please enter the username to associate with the selected IP{pluralize(len(ip_addresses))}:")

        if ok and username:  # Only proceed if the user clicked 'OK' and provided a username
            # Append the username and associated IP(s) to the corresponding database file
            write_lines_to_file(selected_database, "a", [f"{username}={ip}\n" for ip in ip_addresses])

            QMessageBox.information(self, TITLE, f'Selected IP{pluralize(len(ip_addresses))} {ip_addresses} has been added with username "{username}" to UserIP database "{selected_database.relative_to(USERIP_DATABASES_PATH).with_suffix("")}".')
        else:
            # If the user canceled or left the input empty, show an error
            QMessageBox.warning(self, TITLE, "ERROR:\nNo username was provided.")

    def userip_manager__move(self, ip_addresses: list[str], selected_database: Path):
        from Modules.constants.standard import RE_USERIP_INI_PARSER_PATTERN, USERIP_DATABASES_PATH

        # Dictionary to store removed entries by database
        deleted_entries_by_database: dict[Path, list[str]] = {}

        # Iterate over each UserIP database
        for database_path in UserIP_Databases.get_userip_database_filepaths():
            if database_path == selected_database:
                continue

            # Read the database file
            lines = database_path.read_text(encoding="utf-8").splitlines(keepends=True)
            if not lines:
                continue

            # List to store deleted entries in this particular database
            deleted_entries_in_this_database: list[str] = []

            # Remove any lines containing the IP address
            lines_to_keep: list[str] = []
            for line in lines:
                match = RE_USERIP_INI_PARSER_PATTERN.search(line)
                if match:
                    # Extract username and ip using named groups
                    username, ip = match.group("username").strip(), match.group("ip").strip()

                    # Ensure both username and ip are non-empty strings
                    if isinstance(username, str) and isinstance(ip, str) and ip in ip_addresses:
                        deleted_entries_in_this_database.append(line.strip())  # Store the deleted entry
                        continue

                lines_to_keep.append(line)

            if deleted_entries_in_this_database:
                # Only update the database file if there were any deletions
                write_lines_to_file(database_path, "w", lines_to_keep)

                # Store the deleted entries for this database
                deleted_entries_by_database[database_path] = deleted_entries_in_this_database

                # Move the deleted entries to the target database
                write_lines_to_file(selected_database, "a", [f"{entry}\n" for entry in deleted_entries_in_this_database])

        # After processing all databases, show a detailed report
        if deleted_entries_by_database:
            report = f'<b>Selected IP{pluralize(len(ip_addresses))} {ip_addresses} moved from the following UserIP database{pluralize(len(deleted_entries_by_database))} to UserIP database "{selected_database.relative_to(USERIP_DATABASES_PATH).with_suffix("")}":</b><br><br><br>'
            for database_path, deleted_entries in deleted_entries_by_database.items():
                report += f"<b>{database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")}:</b><br>"
                report += "<ul>"
                for entry in deleted_entries:
                    report += f"<li>{entry}</li>"
                report += "</ul><br>"
            report = report.removesuffix("<br>")

            QMessageBox.information(self, TITLE, report)

    def userip_manager__del(self, ip_addresses: list[str]):
        from Modules.constants.standard import RE_USERIP_INI_PARSER_PATTERN, USERIP_DATABASES_PATH

        # Dictionary to store removed entries by database
        deleted_entries_by_database: dict[Path, list[str]] = {}

        # Iterate over each UserIP database
        for database_path in UserIP_Databases.get_userip_database_filepaths():
            # Read the database file
            lines = database_path.read_text(encoding="utf-8").splitlines(keepends=True)
            if not lines:
                continue

            # List to store deleted entries in this particular database
            deleted_entries_in_this_database: list[str] = []

            # Remove any lines containing the IP address
            lines_to_keep: list[str] = []
            for line in lines:
                match = RE_USERIP_INI_PARSER_PATTERN.search(line)
                if match:
                    # Extract username and ip using named groups
                    username, ip = match.group("username").strip(), match.group("ip").strip()

                    # Ensure both username and ip are non-empty strings
                    if isinstance(username, str) and isinstance(ip, str) and ip in ip_addresses:
                        deleted_entries_in_this_database.append(line.strip())  # Store the deleted entry
                        continue

                lines_to_keep.append(line)

            if deleted_entries_in_this_database:
                # Only update the database file if there were any deletions
                write_lines_to_file(database_path, "w", lines_to_keep)

                # Store the deleted entries for this database
                deleted_entries_by_database[database_path] = deleted_entries_in_this_database

        # After processing all databases, show a detailed report
        if deleted_entries_by_database:
            report = f'<b>Selected IP{pluralize(len(ip_addresses))} {ip_addresses} removed from the following UserIP database{pluralize(len(deleted_entries_by_database))}:</b><br><br><br>'
            for database_path, deleted_entries in deleted_entries_by_database.items():
                report += f"<b>{database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")}:</b><br>"
                report += "<ul>"
                for entry in deleted_entries:
                    report += f"<li>{entry}</li>"
                report += "</ul><br>"
            report = report.removesuffix("<br>")

            QMessageBox.information(self, TITLE, report)

    def select_all_cells(self, unselect = False):
        """
        Select or unselect all rows and columns from the table.

        Args:
            unselect: If True, unselect all cells. If False, select all cells.
        """
        selected_model = self.model()
        if not isinstance(selected_model, SessionTableModel):
            raise TypeError(f'Expected "SessionTableModel", got "{type(selected_model).__name__}"')

        selection_model = self.selectionModel()
        if not isinstance(selection_model, QItemSelectionModel):
            raise TypeError(f'Expected "QItemSelectionModel", got "{type(selection_model).__name__}"')

        # Get the top-left and bottom-right QModelIndex for the entire table
        top_left = selected_model.createIndex(0, 0)  # Top-left item (first row, first column)
        bottom_right = selected_model.createIndex(
            selected_model.rowCount() - 1, selected_model.columnCount() - 1
        )  # Bottom-right item (last row, last column)

        # Create a selection range from top-left to bottom-right
        selection = QItemSelection(top_left, bottom_right)

        # Determine selection flag based on the unselect argument
        flag = (
            QItemSelectionModel.SelectionFlag.Deselect
            if unselect
            else QItemSelectionModel.SelectionFlag.Select
        )

        # Apply the selection or deselection
        selection_model.select(selection, flag)

    def select_row_cells(self, row: int, unselect = False):
        """
        Select or unselect all cells in the specified row from the table.

        Args:
            row: The row index to modify selection for.
            unselect: If True, unselect the row. If False, select the row.
        """
        selected_model = self.model()
        if not isinstance(selected_model, SessionTableModel):
            raise TypeError(f'Expected "SessionTableModel", got "{type(selected_model).__name__}"')

        selection_model = self.selectionModel()
        if not isinstance(selection_model, QItemSelectionModel):
            raise TypeError(f'Expected "QItemSelectionModel", got "{type(selection_model).__name__}"')

        top_index = selected_model.createIndex(row, 0)  # First column of the specified row
        bottom_index = selected_model.createIndex(row, selected_model.columnCount() - 1)  # Last column of the specified row

        # Create a selection range for the entire row
        selection = QItemSelection(top_index, bottom_index)

        # Determine selection flag based on the argument
        flag = QItemSelectionModel.SelectionFlag.Deselect if unselect else QItemSelectionModel.SelectionFlag.Select
        selection_model.select(selection, flag)

    def select_column_cells(self, column: int, unselect = False):
        """
        Select or unselect all cells in the specified column from the table.

        Args:
            column: The column index to modify selection for.
            unselect: If True, unselect the column. If False, select the column.
        """
        selected_model = self.model()
        if not isinstance(selected_model, SessionTableModel):
            raise TypeError(f'Expected "SessionTableModel", got "{type(selected_model).__name__}"')

        selection_model = self.selectionModel()
        if not isinstance(selection_model, QItemSelectionModel):
            raise TypeError(f'Expected "QItemSelectionModel", got "{type(selection_model).__name__}"')

        top_index = selected_model.createIndex(0, column)  # First row of the specified column
        bottom_index = selected_model.createIndex(selected_model.rowCount() - 1, column)  # Last row of the specified column

        # Create a selection range for the entire column
        selection = QItemSelection(top_index, bottom_index)

        # Determine selection flag based on the argument
        flag = QItemSelectionModel.SelectionFlag.Deselect if unselect else QItemSelectionModel.SelectionFlag.Select
        selection_model.select(selection, flag)

class GUIWorkerThread(QThread):
    update_signal = pyqtSignal(
        str,
        list,
        list,
        int,
        list,
        list,
        int
    )  # Signal to send updated table data and new size

    def __init__(self,
        connected_table_model: SessionTableModel,
        connected_table_view: SessionTableView,
        disconnected_table_model: SessionTableModel,
        disconnected_table_view: SessionTableView
    ):
        super().__init__()

        self.connected_table_model = connected_table_model
        self.connected_table_view = connected_table_view
        self.disconnected_table_model = disconnected_table_model
        self.disconnected_table_view = disconnected_table_view

    def run(self):
        # While the GUI is not closed, we repeat this loop
        while not gui_closed__event.is_set():
            # Retrieve the sorted column for both tables
            GUIrenderingData.session_connected_sorted_column_name, GUIrenderingData.session_connected_sort_order = self.connected_table_view.get_sorted_column()
            GUIrenderingData.session_disconnected_sorted_column_name, GUIrenderingData.session_disconnected_sort_order = self.disconnected_table_view.get_sorted_column()

            # Wait for the gui_rendering data to be ready (timeout of 0.1 second)
            # If the event is not set within the timeout, just continue
            if not GUIrenderingData.gui_rendering_ready_event.wait(timeout=0.1):
                continue
            GUIrenderingData.gui_rendering_ready_event.clear()

            self.update_signal.emit(
                GUIrenderingData.header_text,
                GUIrenderingData.session_connected_table__processed_data,
                GUIrenderingData.session_connected_table__compiled_colors,
                GUIrenderingData.session_connected_table__num_rows,
                GUIrenderingData.session_disconnected_table__processed_data,
                GUIrenderingData.session_disconnected_table__compiled_colors,
                GUIrenderingData.session_disconnected_table__num_rows
            )

class MainWindow(QMainWindow):
    def __init__(self, screen_width: int, screen_height: int):
        super().__init__()

        # Set up the window
        self.setWindowTitle(f"{TITLE}")
        # Set a minimum size for the window
        self.setMinimumSize(800, 600)
        self.resize_window_for_screen(screen_width, screen_height)

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout for the central widget
        self.main_layout = QVBoxLayout(central_widget)

        # Header text
        self.header_text = QLabel()
        self.header_text.setTextFormat(Qt.TextFormat.RichText)
        self.header_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.header_text.setWordWrap(True)
        self.header_text.setFont(QFont("Courier", 10, QFont.Weight.Bold))

        # Custom header for the Session Connected table with matching background as first column
        self.session_connected_header = QLabel(f"Players connected in your session (0):")
        self.session_connected_header.setTextFormat(Qt.TextFormat.RichText)
        self.session_connected_header.setStyleSheet("background-color: green; color: white; font-size: 16px; font-weight: bold; padding: 5px;")
        self.session_connected_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_connected_header.setFont(QFont("Courier", 9, QFont.Weight.Bold))

        # Create the table model and view
        ## Determine the sort order
        while not GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES:  # Wait for the GUI rendering data to be ready
            gui_closed__event.wait(0.1)
        _sort_column = GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES.index(Settings.GUI_FIELD_CONNECTED_PLAYERS_SORTED_BY)
        _sort_order = Qt.SortOrder.DescendingOrder
        self.connected_table_model = SessionTableModel(GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES, _sort_column, _sort_order)
        self.connected_table_view = SessionTableView(self.connected_table_model, _sort_column, _sort_order)
        del _sort_column, _sort_order
        self.connected_table_model.set_view(self.connected_table_view)

        # Add a horizontal line separator
        self.tables_separator = QFrame(self)
        self.tables_separator.setFrameShape(QFrame.Shape.HLine)
        self.tables_separator.setFrameShadow(QFrame.Shadow.Sunken)  # Optional shadow effect

        # Custom header for the Session Disconnected table with matching background as first column
        self.session_disconnected_header = QLabel(f"Players who've left your session (0):")
        self.session_disconnected_header.setTextFormat(Qt.TextFormat.RichText)
        self.session_disconnected_header.setStyleSheet("background-color: red; color: white; font-size: 16px; font-weight: bold; padding: 5px;")
        self.session_disconnected_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_disconnected_header.setFont(QFont("Courier", 9, QFont.Weight.Bold))

        # Create the table model and view
        ## Determine the sort order
        while not GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES:  # Wait for the GUI rendering data to be ready
            gui_closed__event.wait(0.1)
        _sort_column = GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES.index(Settings.GUI_FIELD_DISCONNECTED_PLAYERS_SORTED_BY)
        if Settings.GUI_FIELD_DISCONNECTED_PLAYERS_SORTED_BY in ("Last Rejoin", "Last Seen"):
            _sort_order = Qt.SortOrder.AscendingOrder
        else:
            _sort_order = Qt.SortOrder.DescendingOrder
        self.disconnected_table_model = SessionTableModel(GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES, _sort_column, _sort_order)
        self.disconnected_table_view = SessionTableView(self.disconnected_table_model, _sort_column, _sort_order)
        del _sort_column, _sort_order
        self.disconnected_table_model.set_view(self.disconnected_table_view)

        # Layout to organize the widgets
        self.main_layout.addWidget(self.header_text)
        self.main_layout.addWidget(self.session_connected_header)
        self.main_layout.addWidget(self.connected_table_view)
        self.main_layout.addWidget(self.tables_separator)
        self.main_layout.addWidget(self.session_disconnected_header)
        self.main_layout.addWidget(self.disconnected_table_view)

        # Create the worker thread for table updates
        self.worker_thread = GUIWorkerThread(
            self.connected_table_model,
            self.connected_table_view,
            self.disconnected_table_model,
            self.disconnected_table_view
        )
        self.worker_thread.update_signal.connect(self.update_gui)
        self.worker_thread.start()

    def closeEvent(self, event: QCloseEvent):
        gui_closed__event.set()  # Signal the thread to stop
        self.worker_thread.quit()  # Stop the QThread
        self.worker_thread.wait()  # Wait for the thread to finish
        event.accept()  # Accept the close event

        terminate_script("EXIT")

    # Custom Methods:

    def resize_window_for_screen(self, screen_width: int, screen_height: int):
        # Resize the window based on screen size
        if screen_width >= 2560 and screen_height >= 1440:
            self.resize(1400, 900)
        elif screen_width >= 1920 and screen_height >= 1080:
            self.resize(1200, 720)
        elif screen_width >= 1024 and screen_height >= 768:
            self.resize(940, 680)

    def update_gui(self,
        header_text: str,
        session_connected_table__processed_data: list[list[str]],
        session_connected_table__compiled_colors: list[list[CellColor]],
        session_connected_table__num_rows: int,
        session_disconnected_table__processed_data: list[list[str]],
        session_disconnected_table__compiled_colors: list[list[CellColor]],
        session_disconnected_table__num_rows: int
    ):
        """Update header text and table data for connected and disconnected players."""
        self.header_text.setText(header_text)

        self.session_connected_header.setText(f"Players connected in your session ({session_connected_table__num_rows}):")

        for processed_data, compiled_colors in zip(session_connected_table__processed_data, session_connected_table__compiled_colors):
            ip_address = processed_data[self.connected_table_model._IP_COLUMN_INDEX].removesuffix(" 👑")

            disconnected_row_index = self.disconnected_table_model.get_row_index_by_ip(ip_address)
            if disconnected_row_index is not None:
                self.disconnected_table_model.delete_row(disconnected_row_index)

            connected_row_index = self.connected_table_model.get_row_index_by_ip(ip_address)
            if connected_row_index is None:
                self.connected_table_model.add_row_without_refresh(processed_data, compiled_colors)
            else:
                self.connected_table_model.update_row_without_refresh(connected_row_index, processed_data, compiled_colors)

        self.connected_table_model.sort_current_column()
        self.connected_table_view.adjust_table_column_widths()

        self.session_disconnected_header.setText(f"Players who've left your session ({session_disconnected_table__num_rows}):")

        for processed_data, compiled_colors in zip(session_disconnected_table__processed_data, session_disconnected_table__compiled_colors):
            ip_address = processed_data[self.disconnected_table_model._IP_COLUMN_INDEX].removesuffix(" 👑")

            connected_row_index = self.connected_table_model.get_row_index_by_ip(ip_address)
            if connected_row_index is not None:
                self.connected_table_model.delete_row(connected_row_index)

            disconnected_row_index = self.disconnected_table_model.get_row_index_by_ip(ip_address)
            if disconnected_row_index is None:
                self.disconnected_table_model.add_row_without_refresh(processed_data, compiled_colors)
            else:
                self.disconnected_table_model.update_row_without_refresh(disconnected_row_index, processed_data, compiled_colors)

        self.disconnected_table_model.sort_current_column()
        self.disconnected_table_view.adjust_table_column_widths()


if __name__ == "__main__":
    window = MainWindow(screen_width, screen_height)
    window.show()

    sys.exit(app.exec())