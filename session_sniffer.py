# pylint: disable=missing-module-docstring,too-many-lines  # noqa: D100
import ast
import dataclasses
import enum
import hashlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import webbrowser
import winsound
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime, timedelta
from operator import attrgetter
from pathlib import Path
from threading import Event, Lock, RLock, Thread
from types import FrameType, TracebackType
from typing import Any, ClassVar, Literal

import colorama
import geoip2.database
import geoip2.errors
import psutil
import requests
from colorama import Fore
from packaging.version import Version
from prettytable import PrettyTable, TableStyle
from pydantic.dataclasses import dataclass
from PyQt6.QtCore import (
    QAbstractItemModel,
    QAbstractTableModel,
    QEasingCurve,
    QEvent,
    QItemSelection,
    QItemSelectionModel,
    QModelIndex,
    QObject,
    QPoint,
    QPropertyAnimation,
    QSize,
    Qt,
    QThread,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QAction,
    QBrush,
    QClipboard,
    QCloseEvent,
    QColor,
    QFont,
    QHoverEvent,
    QIcon,
    QKeyEvent,
    QMouseEvent,
    QPixmap,
)
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QTableView,
    QToolBar,
    QToolTip,
    QVBoxLayout,
    QWidget,
)
from rich.console import Console
from rich.text import Text
from rich.traceback import Traceback

from modules.capture.exceptions import (
    PacketCaptureOverflowError,
    TSharkCrashExceptionError,
    TSharkOutputParsingError,
)
from modules.capture.interface_selection import (
    InterfaceSelectionData,
    show_interface_selection_dialog,
)
from modules.capture.tshark_capture import (
    Packet,
    PacketCapture,
)
from modules.capture.utils.check_tshark_filters import check_broadcast_multicast_support
from modules.capture.utils.npcap_checker import ensure_npcap_installed
from modules.constants.external import LOCAL_TZ
from modules.constants.local import PYPROJECT_DATA, TSHARK_PATH, VERSION
from modules.constants.standalone import (
    GITHUB_RELEASES_URL,
    NETWORK_ADAPTER_DISABLED,
    TITLE,
)
from modules.constants.standard import SETTINGS_PATH
from modules.exceptions import (
    PlayerAlreadyExistsError,
    PlayerNotFoundInRegistryError,
    UnexpectedPlayerCountError,
)
from modules.guis.app import app
from modules.guis.exceptions import (
    InvalidDateFieldConfigurationError,
    PrimaryScreenNotFoundError,
    TableDataConsistencyError,
    UnsupportedSortColumnError,
)
from modules.guis.stylesheets import (
    COMMON_COLLAPSE_BUTTON_STYLESHEET,
    CONNECTED_EXPAND_BUTTON_STYLESHEET,
    CONNECTED_HEADER_CONTAINER_STYLESHEET,
    CONNECTED_HEADER_TEXT_STYLESHEET,
    CUSTOM_CONTEXT_MENU_STYLESHEET,
    DISCONNECTED_EXPAND_BUTTON_STYLESHEET,
    DISCONNECTED_HEADER_CONTAINER_STYLESHEET,
    DISCONNECTED_HEADER_TEXT_STYLESHEET,
    DISCORD_POPUP_EXIT_BUTTON_STYLESHEET,
    DISCORD_POPUP_JOIN_BUTTON_STYLESHEET,
    DISCORD_POPUP_MAIN_STYLESHEET,
)
from modules.guis.utils import get_screen_size
from modules.launcher.package_checker import (
    check_packages_version,
    get_dependencies_from_pyproject,
    get_dependencies_from_requirements,
)
from modules.msgbox import MsgBox
from modules.networking.exceptions import (
    NetworkInterfaceStateMismatchError,
)
from modules.networking.manuf_lookup import MacLookup
from modules.networking.unsafe_https import s
from modules.networking.utils import (
    format_mac_address,
    is_ipv4_address,
    is_mac_address,
    is_valid_non_special_ipv4,
)
from modules.utils import (
    clear_screen,
    dedup_preserve_order,
    format_attribute_error,
    format_triple_quoted_text,
    format_type_error,
    is_pyinstaller_compiled,
    pluralize,
    run_cmd_command,
    run_cmd_script,
    set_window_title,
    validate_and_strip_balanced_outer_parens,
    validate_file,
)

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M',
    handlers=[
        logging.FileHandler('error.log'),
    ],
)
logging.captureWarnings(capture=True)
logger = logging.getLogger(__name__)


@dataclass(frozen=True, config={'arbitrary_types_allowed': True}, slots=True)
class ExceptionInfo:
    exc_type: type[BaseException]
    exc_value: BaseException
    exc_traceback: TracebackType | None


def terminate_script(
    terminate_method: Literal['EXIT', 'SIGINT', 'THREAD_RAISED'],
    msgbox_crash_text: str | None = None,
    stdout_crash_text: str | None = None,
    exception_info: ExceptionInfo | None = None,
    *,
    terminate_gracefully: bool = True,
    force_terminate_errorlevel: int | Literal[False] | None = False,
):
    from modules.utils import terminate_process_tree

    def should_terminate_gracefully() -> bool:
        if terminate_gracefully is False:
            return False

        for thread_name in ('capture_core__thread', 'rendering_core__thread', 'hostname_core__thread', 'iplookup_core__thread', 'pinger_core__thread'):
            if thread_name in globals():
                thread = globals()[thread_name]
                if isinstance(thread, Thread) and thread.is_alive():
                    return False

        # TODO(BUZZARDGTA): Gracefully exit the script even when the `capture` module is running.
        return False

    ScriptControl.set_crashed(None if stdout_crash_text is None else f'\n\n{stdout_crash_text}\n')

    if exception_info:
        logger.error('Uncaught exception: %s: %s', exception_info.exc_type.__name__, exception_info.exc_value)

        console = Console()

        traceback_message = Traceback.from_exception(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback)
        console.print(traceback_message)

        error_message = Text.from_markup(
            (
                '\n\n\nAn unexpected (uncaught) error occurred. [bold]Please kindly report it to:[/bold]\n'
                '[link=https://github.com/BUZZARDGTA/Session-Sniffer/issues]'
                'https://github.com/BUZZARDGTA/Session-Sniffer/issues[/link].\n\n'
                'DEBUG:\n'
                f'VERSION={globals().get("VERSION", "Unknown Version")}'  # Define a default value for VERSION if it's not defined
            ),
            style='white',
        )
        console.print(error_message)

    if stdout_crash_text is not None:
        print(ScriptControl.get_message())

    if msgbox_crash_text is not None:
        msgbox_title = TITLE
        msgbox_message = msgbox_crash_text
        msgbox_style = MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONERROR | MsgBox.Style.MB_SYSTEMMODAL

        MsgBox.show(msgbox_title, msgbox_message, msgbox_style)
        time.sleep(1)

    # If the termination method is "EXIT", do not sleep unless crash messages are present
    need_sleep = True
    if terminate_method == 'EXIT' and msgbox_crash_text is None and stdout_crash_text is None:
        need_sleep = False
    if need_sleep:
        time.sleep(3)

    if should_terminate_gracefully():
        if force_terminate_errorlevel is False:
            errorlevel = 1 if terminate_method == 'THREAD_RAISED' else 0
        else:
            errorlevel = force_terminate_errorlevel if force_terminate_errorlevel is not None else 0
        sys.exit(errorlevel)

    terminate_process_tree()


def handle_exception(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
    """Handle exceptions for the main script (not threads)."""
    if issubclass(exc_type, KeyboardInterrupt):
        return

    exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
    terminate_script('EXIT', 'An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\nhttps://github.com/BUZZARDGTA/Session-Sniffer/issues', exception_info=exception_info)


def handle_sigint(_sig: int, _frame: FrameType | None) -> None:
    if not ScriptControl.has_crashed():
        # Block CTRL+C if script is already crashing under control
        print(f'\n{Fore.YELLOW}Ctrl+C pressed. Exiting script ...{Fore.RESET}')
        terminate_script('SIGINT')


sys.excepthook = handle_exception
signal.signal(signal.SIGINT, handle_sigint)


class ScriptControl:
    _lock: ClassVar = Lock()
    _crashed: ClassVar[bool] = False
    _message: ClassVar[str | None] = None

    @classmethod
    def set_crashed(cls, message: str | None = None) -> None:
        with cls._lock:
            cls._crashed = True
            cls._message = message

    @classmethod
    def reset_crashed(cls) -> None:
        with cls._lock:
            cls._crashed = False
            cls._message = None

    @classmethod
    def has_crashed(cls) -> bool:
        with cls._lock:
            return cls._crashed

    @classmethod
    def get_message(cls) -> str | None:
        with cls._lock:
            return cls._message


class ThreadsExceptionHandler:
    """Handle exceptions raised within threads and provide additional functionality for managing thread execution.

    This class is designed to overcome the limitation where threads run independently from the main process, which continues execution without waiting for thread completion.

    Attributes:
        raising_function (str | None): The name of the function where the exception was raised.
        raising_exc_type (type[BaseException] | None): The type of the raised exception.
        raising_exc_value (BaseException | None): The value of the raised exception.
        raising_exc_traceback (TracebackType | None): The traceback information for the raised exception.
    """
    raising_function:      ClassVar[str                 | None] = None
    raising_exc_type:      ClassVar[type[BaseException] | None] = None
    raising_exc_value:     ClassVar[BaseException       | None] = None
    raising_exc_traceback: ClassVar[TracebackType       | None] = None

    def __enter__(self) -> None:
        """Enter the runtime context related to this object."""

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_traceback: TracebackType | None) -> bool:
        """Exit method called upon exiting the 'with' block.

        Args:
            exc_type (type[BaseException] | None): The type of the raised exception.
            exc_value (BaseException | None): The value of the raised exception.
            exc_traceback (TracebackType | None): The traceback information of the raised exception.

        Returns:
            bool: True to suppress the exception from propagating further.
        """
        # Return False to allow normal execution if no exception occurred
        if exc_type is None or exc_value is None:
            return False

        # Handle exception details
        ThreadsExceptionHandler.raising_exc_type = exc_type
        ThreadsExceptionHandler.raising_exc_value = exc_value
        ThreadsExceptionHandler.raising_exc_traceback = exc_traceback

        # Extract the failed function name from the traceback safely
        if exc_traceback is not None:
            tb = exc_traceback
            while tb.tb_next:
                tb = tb.tb_next
            ThreadsExceptionHandler.raising_function = tb.tb_frame.f_code.co_name
        else:
            ThreadsExceptionHandler.raising_function = '<unknown>'

        # Create the exception info and terminate the script
        exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
        terminate_script(
            'THREAD_RAISED',
            (
                'An unexpected (uncaught) error occurred.\n\n'
                'Please kindly report it to:\n'
                'https://github.com/BUZZARDGTA/Session-Sniffer/issues'
            ),
            exception_info=exception_info,
        )

        # Suppress the exception from propagating
        return True


@dataclass
class DefaultSettings:  # pylint: disable=too-many-instance-attributes,invalid-name
    """Class containing default setting values."""
    CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT: bool = True
    CAPTURE_INTERFACE_NAME: str | None = None
    CAPTURE_IP_ADDRESS: str | None = None
    CAPTURE_MAC_ADDRESS: str | None = None
    CAPTURE_ARP: bool = True
    CAPTURE_BLOCK_THIRD_PARTY_SERVERS: bool = True
    CAPTURE_PROGRAM_PRESET: str | None = None
    CAPTURE_OVERFLOW_TIMER: float = 3.0
    CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER: str | None = None
    CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER: str | None = None
    GUI_SESSIONS_LOGGING: bool = True
    GUI_RESET_PORTS_ON_REJOINS: bool = True
    GUI_FIELDS_TO_HIDE: tuple[str, ...] = ('PPM', 'Middle Ports', 'First Port', 'Continent', 'R. Code', 'City', 'District', 'ZIP Code', 'Lat', 'Lon', 'Time Zone', 'Offset', 'Currency', 'Organization', 'ISP', 'AS', 'ASN')
    GUI_DATE_FIELDS_SHOW_DATE: bool = False
    GUI_DATE_FIELDS_SHOW_TIME: bool = False
    GUI_DATE_FIELDS_SHOW_ELAPSED: bool = True
    GUI_FIELD_SHOW_COUNTRY_CODE: bool = True
    GUI_FIELD_SHOW_CONTINENT_CODE: bool = True
    GUI_DISCONNECTED_PLAYERS_TIMER: float = 10.0
    DISCORD_PRESENCE: bool = True
    SHOW_DISCORD_POPUP: bool = True
    UPDATER_CHANNEL: str | None = 'Stable'


class Settings(DefaultSettings):
    ALL_SETTINGS: ClassVar = (
        'CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT',
        'CAPTURE_INTERFACE_NAME',
        'CAPTURE_IP_ADDRESS',
        'CAPTURE_MAC_ADDRESS',
        'CAPTURE_ARP',
        'CAPTURE_BLOCK_THIRD_PARTY_SERVERS',
        'CAPTURE_PROGRAM_PRESET',
        'CAPTURE_OVERFLOW_TIMER',
        'CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER',
        'CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER',
        'GUI_SESSIONS_LOGGING',
        'GUI_RESET_PORTS_ON_REJOINS',
        'GUI_FIELDS_TO_HIDE',
        'GUI_DATE_FIELDS_SHOW_DATE',
        'GUI_DATE_FIELDS_SHOW_TIME',
        'GUI_DATE_FIELDS_SHOW_ELAPSED',
        'GUI_FIELD_SHOW_COUNTRY_CODE',
        'GUI_FIELD_SHOW_CONTINENT_CODE',
        'GUI_DISCONNECTED_PLAYERS_TIMER',
        'DISCORD_PRESENCE',
        'SHOW_DISCORD_POPUP',
        'UPDATER_CHANNEL',
    )

    _ALL_SETTINGS_SET: ClassVar = frozenset(ALL_SETTINGS)

    GUI_FIELDS_MAPPING: ClassVar = {
        'Usernames': 'usernames',
        'First Seen': 'datetime.first_seen',
        'Last Rejoin': 'datetime.last_rejoin',
        'Last Seen': 'datetime.last_seen',
        'Rejoins': 'rejoins',
        'T. Packets': 'total_packets',
        'Packets': 'packets',
        'PPS': 'pps.rate',
        'PPM': 'ppm.rate',
        'IP Address': 'ip',
        'Hostname': 'reverse_dns.hostname',
        'Last Port': 'ports.last',
        'Middle Ports': 'ports.middle',
        'First Port': 'ports.first',
        'Continent': 'iplookup.ipapi.continent',
        'Country': 'iplookup.geolite2.country',
        'Region': 'iplookup.ipapi.region',
        'R. Code': 'iplookup.ipapi.region_code',
        'City': 'iplookup.geolite2.city',
        'District': 'iplookup.ipapi.district',
        'ZIP Code': 'iplookup.ipapi.zip_code',
        'Lat': 'iplookup.ipapi.lat',
        'Lon': 'iplookup.ipapi.lon',
        'Time Zone': 'iplookup.ipapi.time_zone',
        'Offset': 'iplookup.ipapi.offset',
        'Currency': 'iplookup.ipapi.currency',
        'Organization': 'iplookup.ipapi.org',
        'ISP': 'iplookup.ipapi.isp',
        'ASN / ISP': 'iplookup.geolite2.asn',
        'AS': 'iplookup.ipapi.asn',
        'ASN': 'iplookup.ipapi.as_name',
        'Mobile': 'iplookup.ipapi.mobile',
        'VPN': 'iplookup.ipapi.proxy',
        'Hosting': 'iplookup.ipapi.hosting',
        'Pinging': 'ping.is_pinging',
    }
    GUI_FORCED_FIELDS          : ClassVar = ('Usernames', 'First Seen', 'Last Rejoin', 'Last Seen', 'Rejoins', 'T. Packets', 'Packets',               'IP Address')
    GUI_HIDEABLE_FIELDS        : ClassVar = (                                                                                           'PPS', 'PPM',               'Hostname', 'Last Port', 'Middle Ports', 'First Port', 'Continent', 'Country', 'Region', 'R. Code', 'City', 'District', 'ZIP Code', 'Lat', 'Lon', 'Time Zone', 'Offset', 'Currency', 'Organization', 'ISP', 'ASN / ISP', 'AS', 'ASN', 'Mobile', 'VPN', 'Hosting', 'Pinging')
    GUI_ALL_CONNECTED_FIELDS   : ClassVar = ('Usernames', 'First Seen', 'Last Rejoin',              'Rejoins', 'T. Packets', 'Packets', 'PPS', 'PPM', 'IP Address', 'Hostname', 'Last Port', 'Middle Ports', 'First Port', 'Continent', 'Country', 'Region', 'R. Code', 'City', 'District', 'ZIP Code', 'Lat', 'Lon', 'Time Zone', 'Offset', 'Currency', 'Organization', 'ISP', 'ASN / ISP', 'AS', 'ASN', 'Mobile', 'VPN', 'Hosting', 'Pinging')
    GUI_ALL_DISCONNECTED_FIELDS: ClassVar = ('Usernames', 'First Seen', 'Last Rejoin', 'Last Seen', 'Rejoins', 'T. Packets', 'Packets',               'IP Address', 'Hostname', 'Last Port', 'Middle Ports', 'First Port', 'Continent', 'Country', 'Region', 'R. Code', 'City', 'District', 'ZIP Code', 'Lat', 'Lon', 'Time Zone', 'Offset', 'Currency', 'Organization', 'ISP', 'ASN / ISP', 'AS', 'ASN', 'Mobile', 'VPN', 'Hosting', 'Pinging')

    @classmethod
    def iterate_over_settings(cls) -> Iterator[tuple[str, Any]]:
        """Iterate over all settings and their current values."""
        for setting_name in cls.ALL_SETTINGS:
            yield setting_name, getattr(cls, setting_name)

    @classmethod
    def get_settings_length(cls) -> int:
        """Get the total number of settings."""
        return len(cls.ALL_SETTINGS)

    @classmethod
    def has_setting(cls, setting_name: str) -> bool:
        """Check if a setting exists."""
        return setting_name in cls._ALL_SETTINGS_SET

    @classmethod
    def reconstruct_settings(cls) -> None:
        print('\nCorrect reconstruction of "Settings.ini" ...')
        text = format_triple_quoted_text(f"""
            ;;-----------------------------------------------------------------------------
            ;; {TITLE} Configuration Settings
            ;;-----------------------------------------------------------------------------
            ;; Lines starting with ";" or "#" symbols are commented lines.
            ;;
            ;; For detailed explanations of each setting, please refer to the following documentation:
            ;; https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#script-settings-configuration
            ;;-----------------------------------------------------------------------------
        """, add_trailing_newline=True)
        for setting_name, setting_value in cls.iterate_over_settings():
            text += f'{setting_name}={setting_value}\n'
        SETTINGS_PATH.write_text(text, encoding='utf-8')

    @staticmethod
    def parse_settings_ini_file(ini_path: Path) -> tuple[dict[str, str], bool]:
        from modules.constants.standard import RE_SETTINGS_INI_PARSER_PATTERN

        def process_ini_line_output(line: str) -> str:
            return line.rstrip('\n')

        validate_file(ini_path)

        ini_data = ini_path.read_text('utf-8')

        need_rewrite_ini = False
        ini_database: dict[str, str] = {}

        for line in map(process_ini_line_output, ini_data.splitlines(keepends=False)):
            corrected_line = line.strip()
            if corrected_line != line:
                need_rewrite_ini = True

            match = RE_SETTINGS_INI_PARSER_PATTERN.search(corrected_line)
            if not match:
                continue

            setting_name = match.group('key')
            if not isinstance(setting_name, str):
                raise TypeError(format_type_error(setting_name, str))
            setting_value = match.group('value')
            if not isinstance(setting_value, str):
                raise TypeError(format_type_error(setting_value, str))

            corrected_setting_name = setting_name.strip()
            if not corrected_setting_name:
                continue

            if corrected_setting_name != setting_name:
                need_rewrite_ini = True

            corrected_setting_value = setting_value.strip()
            if not corrected_setting_value:
                continue

            if corrected_setting_value != setting_value:
                need_rewrite_ini = True

            if corrected_setting_name in ini_database:
                need_rewrite_ini = True  # Settings file needs to be rewritten as it contains duplicate settings
                continue

            ini_database[corrected_setting_name] = corrected_setting_value

        return ini_database, need_rewrite_ini

    @classmethod
    def load_from_settings_file(cls, settings_path: Path) -> None:
        from modules.utils import (
            check_case_insensitive_and_exact_match,
            custom_str_to_bool,
            custom_str_to_nonetype,
        )
        from modules.utils_exceptions import (
            InvalidBooleanValueError,
            InvalidNoneTypeValueError,
            NoMatchFoundError,
        )

        matched_settings_count = 0

        try:
            settings, need_rewrite_settings = cls.parse_settings_ini_file(settings_path)
        except FileNotFoundError:
            need_rewrite_settings = True
        else:
            for setting_name, setting_value in settings.items():
                if not cls.has_setting(setting_name):
                    need_rewrite_settings = True
                    continue

                matched_settings_count += 1
                need_rewrite_current_setting = False

                if setting_name == 'CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT':
                    try:
                        Settings.CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'CAPTURE_INTERFACE_NAME':
                    try:
                        Settings.CAPTURE_INTERFACE_NAME, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.CAPTURE_INTERFACE_NAME = setting_value  # pyright: ignore[reportConstantRedefinition]
                elif setting_name == 'CAPTURE_IP_ADDRESS':
                    try:
                        Settings.CAPTURE_IP_ADDRESS, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        if is_ipv4_address(setting_value):
                            Settings.CAPTURE_IP_ADDRESS = setting_value  # pyright: ignore[reportConstantRedefinition]
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_MAC_ADDRESS':
                    try:
                        Settings.CAPTURE_MAC_ADDRESS, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        formatted_mac_address = format_mac_address(setting_value)
                        if is_mac_address(formatted_mac_address):
                            if formatted_mac_address != setting_value:
                                need_rewrite_settings = True
                            Settings.CAPTURE_MAC_ADDRESS = formatted_mac_address  # pyright: ignore[reportConstantRedefinition]
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_ARP':
                    try:
                        Settings.CAPTURE_ARP, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'CAPTURE_BLOCK_THIRD_PARTY_SERVERS':
                    try:
                        Settings.CAPTURE_BLOCK_THIRD_PARTY_SERVERS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'CAPTURE_PROGRAM_PRESET':
                    try:
                        Settings.CAPTURE_PROGRAM_PRESET, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        try:
                            case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, ('GTA5', 'Minecraft'))
                            Settings.CAPTURE_PROGRAM_PRESET = normalized_match  # pyright: ignore[reportConstantRedefinition]
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        except NoMatchFoundError:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_OVERFLOW_TIMER':
                    try:
                        capture_overflow_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if capture_overflow_timer >= 1:
                            Settings.CAPTURE_OVERFLOW_TIMER = capture_overflow_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER':
                    try:
                        Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER = validate_and_strip_balanced_outer_parens(setting_value)  # pyright: ignore[reportConstantRedefinition]
                        if setting_value != Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER':
                    try:
                        Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER = validate_and_strip_balanced_outer_parens(setting_value)  # pyright: ignore[reportConstantRedefinition]
                        if setting_value != Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER:
                            need_rewrite_settings = True
                elif setting_name == 'GUI_SESSIONS_LOGGING':
                    try:
                        Settings.GUI_SESSIONS_LOGGING, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_RESET_PORTS_ON_REJOINS':
                    try:
                        Settings.GUI_RESET_PORTS_ON_REJOINS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_FIELDS_TO_HIDE':
                    try:
                        gui_fields_to_hide = ast.literal_eval(setting_value)
                    except (ValueError, SyntaxError):
                        need_rewrite_settings = True
                    else:
                        if isinstance(gui_fields_to_hide, tuple) and all(isinstance(item, str) for item in gui_fields_to_hide):  # pyright: ignore[reportUnknownVariableType]
                            filtered_gui_fields_to_hide: list[str] = []

                            for value in gui_fields_to_hide:  # pyright: ignore[reportUnknownVariableType]
                                try:
                                    case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, Settings.GUI_HIDEABLE_FIELDS)  # pyright: ignore[reportUnknownArgumentType]
                                    filtered_gui_fields_to_hide.append(normalized_match)
                                    if not case_sensitive_match:
                                        need_rewrite_current_setting = True
                                except NoMatchFoundError:
                                    need_rewrite_settings = True

                            Settings.GUI_FIELDS_TO_HIDE = tuple(filtered_gui_fields_to_hide)
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'GUI_DATE_FIELDS_SHOW_DATE':
                    try:
                        Settings.GUI_DATE_FIELDS_SHOW_DATE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_DATE_FIELDS_SHOW_TIME':
                    try:
                        Settings.GUI_DATE_FIELDS_SHOW_TIME, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_DATE_FIELDS_SHOW_ELAPSED':
                    try:
                        Settings.GUI_DATE_FIELDS_SHOW_ELAPSED, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_FIELD_SHOW_CONTINENT_CODE':
                    try:
                        Settings.GUI_FIELD_SHOW_CONTINENT_CODE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_FIELD_SHOW_COUNTRY_CODE':
                    try:
                        Settings.GUI_FIELD_SHOW_COUNTRY_CODE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_DISCONNECTED_PLAYERS_TIMER':
                    try:
                        player_disconnected_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if player_disconnected_timer >= 3.0:  # noqa: PLR2004
                            Settings.GUI_DISCONNECTED_PLAYERS_TIMER = player_disconnected_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'DISCORD_PRESENCE':
                    try:
                        Settings.DISCORD_PRESENCE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'SHOW_DISCORD_POPUP':
                    try:
                        Settings.SHOW_DISCORD_POPUP, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'UPDATER_CHANNEL':
                    try:
                        Settings.UPDATER_CHANNEL, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        try:
                            case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, ('Stable', 'RC'))
                            Settings.UPDATER_CHANNEL = normalized_match  # pyright: ignore[reportConstantRedefinition]
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        except NoMatchFoundError:
                            need_rewrite_settings = True

                if need_rewrite_current_setting:
                    need_rewrite_settings = True

            if matched_settings_count != cls.get_settings_length():
                need_rewrite_settings = True

        if (
            Settings.GUI_DATE_FIELDS_SHOW_DATE is False
            and Settings.GUI_DATE_FIELDS_SHOW_TIME is False
            and Settings.GUI_DATE_FIELDS_SHOW_ELAPSED is False
        ):
            need_rewrite_settings = True

            MsgBox.show(
                title=TITLE,
                text=format_triple_quoted_text("""
                    ERROR in your custom "Settings.ini" file:

                    At least one of these settings must be set to "True" value:
                    <GUI_DATE_FIELDS_SHOW_DATE>
                    <GUI_DATE_FIELDS_SHOW_TIME>
                    <GUI_DATE_FIELDS_SHOW_ELAPSED>

                    Default values will be applied to fix this issue.
                """),
                style=MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND,
            )

            for setting_name in (
                'GUI_DATE_FIELDS_SHOW_DATE',
                'GUI_DATE_FIELDS_SHOW_TIME',
                'GUI_DATE_FIELDS_SHOW_ELAPSED',
            ):
                setattr(Settings, setting_name, getattr(DefaultSettings, setting_name))

        if need_rewrite_settings:
            cls.reconstruct_settings()


@dataclass(slots=True, kw_only=True, eq=True)
class ARPEntry:
    ip_address: str
    mac_address: str
    organization_name: str | None = None


@dataclass(kw_only=True, slots=True)
class Interface:
    index:        int
    ip_enabled:   bool | None    = None
    state:        int  | None    = None
    name:         str  | None    = None
    mac_address:  str  | None    = None
    manufacturer: str  | None    = None
    packets_sent: int  | None    = None
    packets_recv: int  | None    = None
    descriptions: list[str]      = dataclasses.field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]
    ip_addresses: list[str]      = dataclasses.field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]
    arp_entries:  list[ARPEntry] = dataclasses.field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]

    def add_arp_entry(self, arp_entry: ARPEntry) -> bool:
        """Add an ARP entry for the given interface."""
        if arp_entry in self.arp_entries:
            return False

        self.arp_entries.append(arp_entry)
        return True

    def get_arp_entries(self) -> list[ARPEntry]:
        """Get ARP entries for the given interface."""
        return self.arp_entries

    def is_interface_inactive(self) -> bool:
        """Determine if an interface is inactive based on lack of traffic, IP addresses, and identifying details."""
        # Check if interface is disabled
        if self.ip_enabled is False or self.state == NETWORK_ADAPTER_DISABLED:
            return True

        # Check if all identifying details and traffic data are missing
        return (
            self.mac_address is None
            and self.packets_sent in {None, 0}
            and self.packets_recv in {None, 0}
            and not self.descriptions
            and not self.ip_addresses
            and not self.arp_entries
        )

    # ─────────────────────────────────────────────────────────────
    # Update/Add Methods
    # ─────────────────────────────────────────────────────────────

    def update_ip_enabled(self, *, new_value: bool | None) -> bool:
        if new_value is None:
            return False

        if self.ip_enabled is not None and self.ip_enabled != new_value:
            raise NetworkInterfaceStateMismatchError(field_name='ip_enabled', existing_value=self.ip_enabled, new_value=new_value)
        self.ip_enabled = new_value
        return True

    def update_state(self, new_value: int | None) -> bool:
        if new_value is None:
            return False

        if self.state is not None and self.state != new_value:
            raise NetworkInterfaceStateMismatchError(field_name='state', existing_value=self.state, new_value=new_value)
        self.state = new_value
        return True

    def update_name(self, new_value: str | None) -> bool:
        if new_value is None:
            return False

        if self.name is not None and self.name != new_value:
            raise NetworkInterfaceStateMismatchError(field_name='name', existing_value=self.name, new_value=new_value)
        self.name = new_value
        return True

    def update_mac_address(self, new_value: str | None) -> bool:
        if new_value is None:
            return False

        if self.mac_address is not None and self.mac_address != new_value:
            raise NetworkInterfaceStateMismatchError(field_name='mac_address', existing_value=self.mac_address, new_value=new_value)
        self.mac_address = new_value
        return True

    def update_manufacturer(self, new_value: str | None) -> bool:
        if new_value is None:
            return False

        if self.manufacturer is not None and self.manufacturer != new_value:
            raise NetworkInterfaceStateMismatchError(field_name='manufacturer', existing_value=self.manufacturer, new_value=new_value)
        self.manufacturer = new_value
        return True

    def update_packets_sent(self, new_value: int | None) -> bool:
        if new_value is None:
            return False

        if self.packets_sent is not None and self.packets_sent != new_value:
            raise NetworkInterfaceStateMismatchError(field_name='packets_sent', existing_value=self.packets_sent, new_value=new_value)
        self.packets_sent = new_value
        return True

    def update_packets_recv(self, new_value: int | None) -> bool:
        if new_value is None:
            return False

        if self.packets_recv is not None and self.packets_recv != new_value:
            raise NetworkInterfaceStateMismatchError(field_name='packets_recv', existing_value=self.packets_recv, new_value=new_value)
        self.packets_recv = new_value
        return True

    def add_description(self, new_value: str | None) -> bool:
        if new_value is None:
            return False

        normalized_new = new_value.casefold()
        if normalized_new not in {desc.casefold() for desc in self.descriptions}:
            self.descriptions.append(new_value)
            return True

        return False

    def add_ip_address(self, new_value: str | None) -> bool:
        if new_value is None:
            return False

        if new_value not in self.ip_addresses:
            self.ip_addresses.append(new_value)
            return True

        return False


class AllInterfaces:
    all_interfaces: ClassVar[dict[int, Interface]] = {}
    _name_map: ClassVar[dict[str, int]] = {}

    @classmethod
    def iterate(cls) -> Iterator[Interface]:
        """Yield each interface from `all_interfaces`.

        This is an iterator that will provide all interfaces stored in the dictionary.
        The iteration will be done over the dictionary values (the Interface objects).

        Yields:
            Interface: Each interface from `all_interfaces`.
        """
        yield from cls.all_interfaces.values()

    @classmethod
    def get_interface(cls, index: int) -> Interface | None:
        """Retrieve an interface by its `index`.

        Args:
            index (int): The index of the interface to retrieve.

        Returns:
            Interface | None: The interface matching the index, or None if not found.
        """
        return cls.all_interfaces.get(index)

    @classmethod
    def get_interface_by_name(cls, name: str) -> Interface | None:
        """Retrieve an interface by its `name`, case-insensitively.

        Args:
            name (str): The name of the interface to retrieve.

        Returns:
            Interface | None: The interface matching the name, or None if not found.
        """
        normalized_name = name.casefold()
        index = cls._name_map.get(normalized_name)
        if index is not None:
            return cls.get_interface(index)
        return None

    @classmethod
    def add_interface(cls, new_interface: Interface) -> bool:
        """Add a new interface to the dictionary if it doesn't already exist.

        Args:
            new_interface (Interface): The interface object to add.

        Returns:
            bool: `True` if the interface was added, `False` if it already exists.
        """
        if new_interface.index not in cls.all_interfaces:
            cls.all_interfaces[new_interface.index] = new_interface
            if new_interface.name:
                cls._name_map[new_interface.name.casefold()] = new_interface.index
            return True
        return False

    @classmethod
    def delete_interface(cls, index: int) -> bool:
        """Delete an interface by its `index`.

        Args:
            index (int): The index of the interface to delete.

        Returns:
            bool: `True` if the interface was deleted, `False` if no matching interface was found.
        """
        interface = cls.all_interfaces.pop(index, None)
        if interface:
            if interface.name:
                cls._name_map.pop(interface.name.casefold(), None)
            return True
        return False


class ThirdPartyServers(enum.Enum):
    PC_DISCORD = ('66.22.196.0/22', '66.22.200.0/21', '66.22.208.0/20', '66.22.224.0/20', '66.22.240.0/21', '66.22.248.0/24')
    PC_VALVE = ('103.10.124.0/23', '103.28.54.0/23', '146.66.152.0/21', '155.133.224.0/19', '162.254.192.0/21', '185.25.180.0/22', '205.196.6.0/24')  # Valve = Steam
    PC_GOOGLE = ('34.0.0.0/9', '34.128.0.0/10', '35.184.0.0/13', '35.192.0.0/11', '35.224.0.0/12', '35.240.0.0/13')
    PC_MULTICAST = ('224.0.0.0/4',)
    PC_UK_MINISTRY_OF_DEFENCE = ('25.0.0.0/8',)
    PC_SERVERS_COM = ('173.237.26.0/24',)
    PC_OTHERS = ('113.117.15.193/32',)
    PS_SONY_INTERACTIVE  = ('104.142.128.0/17',)
    PS_AMAZON = ('34.192.0.0/10', '44.192.0.0/10', '52.0.0.0/10', '52.64.0.0/12', '52.80.0.0/13', '52.88.0.0/14')
    GTAV_TAKETWO = ('104.255.104.0/22', '185.56.64.0/22', '192.81.240.0/21')
    GTAV_PC_MICROSOFT = ('52.139.128.0/18',)
    GTAV_PC_DOD_NETWORK_INFORMATION_CENTER = ('26.0.0.0/8',)
    GTAV_PC_BATTLEYE = ('51.89.97.102/32', '51.89.99.255/32')
    GTAV_XBOXONE_MICROSOFT = ('40.74.0.0/18', '52.159.128.0/17', '52.160.0.0/16')
    MINECRAFTBEDROCKEDITION_PC_PS4_MICROSOFT = ('20.202.0.0/24', '20.224.0.0/16', '168.61.142.128/25', '168.61.143.0/24', '168.61.144.0/20', '168.61.160.0/19')

    @classmethod
    def get_all_ip_ranges(cls) -> list[str]:
        """Return a flat list of all IP ranges from the Enum."""
        return [ip_range for server in cls for ip_range in server.value]


@dataclass(kw_only=True, slots=True)
class PlayerReverseDNS:
    is_initialized: bool = False

    hostname: Literal['...'] | str = '...'  # noqa: PYI051


@dataclass(kw_only=True, slots=True)
class PlayerPPS:
    """Class to manage player packets per second (PPS) calculations."""
    is_first_calculation: bool = True
    last_update_time: float = dataclasses.field(default_factory=time.monotonic)
    counter: int = 0
    rate: int = 0

    def update_rate(self, counter: int) -> None:
        """Update the current rate."""
        self.is_first_calculation = False
        self.last_update_time = time.monotonic()
        self.counter = 0
        self.rate = counter

    def reset(self) -> None:
        """Resets the PlayerPPS to its initial state."""
        self.is_first_calculation = True
        self.last_update_time = time.monotonic()
        self.counter = 0
        self.rate = 0


@dataclass(kw_only=True, slots=True)
class PlayerPPM:
    """Class to manage player packets per second (PPM) calculations."""
    is_first_calculation: bool = True
    last_update_time: float = dataclasses.field(default_factory=time.monotonic)
    counter: int = 0
    rate: int = 0

    def update_rate(self, counter: int) -> None:
        """Update the current rate."""
        self.is_first_calculation = False
        self.last_update_time = time.monotonic()
        self.counter = 0
        self.rate = counter

    def reset(self) -> None:
        """Resets the PlayerPPS to its initial state."""
        self.is_first_calculation = True
        self.last_update_time = time.monotonic()
        self.counter = 0
        self.rate = 0


@dataclass(kw_only=True, slots=True)
class PlayerPorts:
    all: list[int]
    first: int
    middle: list[int]
    last: int

    @classmethod
    def from_packet_port(cls, port: int) -> 'PlayerPorts':
        return cls(
            all=[port],
            first=port,
            middle=[],
            last=port,
        )

    def reset(self, port: int) -> None:
        self.all.clear()
        self.all.append(port)
        self.first = port
        self.middle.clear()
        self.last = port


@dataclass(kw_only=True, slots=True)
class PlayerDateTime:
    first_seen: datetime
    last_rejoin: datetime
    last_seen: datetime

    @classmethod
    def from_packet_datetime(cls, packet_datetime: datetime) -> 'PlayerDateTime':
        return cls(
            first_seen=packet_datetime,
            last_rejoin=packet_datetime,
            last_seen=packet_datetime,
        )


@dataclass(kw_only=True, slots=True)
class PlayerGeoLite2:
    is_initialized: bool = False

    country:      Literal['...', 'N/A'] | str = '...'  # noqa: PYI051
    country_code: Literal['...', 'N/A'] | str = '...'  # noqa: PYI051
    city:         Literal['...', 'N/A'] | str = '...'  # noqa: PYI051
    asn:          Literal['...', 'N/A'] | str = '...'  # noqa: PYI051


@dataclass(kw_only=True, slots=True)
class PlayerIPAPI:  # pylint: disable=too-many-instance-attributes
    is_initialized: bool = False

    continent:      Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    continent_code: Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    country:        Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    country_code:   Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    region:         Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    region_code:    Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    city:           Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    district:       Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    zip_code:       Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    lat:            Literal['...', 'N/A'] | float | int = '...'
    lon:            Literal['...', 'N/A'] | float | int = '...'
    time_zone:      Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    offset:         Literal['...', 'N/A'] | int         = '...'
    currency:       Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    org:            Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    isp:            Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    asn:            Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    as_name:        Literal['...', 'N/A'] | str         = '...'  # noqa: PYI051
    mobile:         Literal['...', 'N/A'] | bool        = '...'
    proxy:          Literal['...', 'N/A'] | bool        = '...'
    hosting:        Literal['...', 'N/A'] | bool        = '...'


@dataclass(config={'arbitrary_types_allowed': True}, kw_only=True, slots=True)
class PlayerCountryFlag:
    pixmap: QPixmap
    icon: QIcon


@dataclass(kw_only=True, slots=True)
class PlayerIPLookup:
    geolite2: PlayerGeoLite2 = dataclasses.field(default_factory=PlayerGeoLite2)
    ipapi: PlayerIPAPI = dataclasses.field(default_factory=PlayerIPAPI)


@dataclass(kw_only=True, slots=True)
class PlayerPing:  # pylint: disable=too-many-instance-attributes
    is_initialized: bool = False

    is_pinging:          Literal['...'] | bool         = '...'
    ping_times:          Literal['...'] | list[float]  = '...'
    packets_transmitted: Literal['...'] | int   | None = '...'
    packets_received:    Literal['...'] | int   | None = '...'
    packet_duplicates:   Literal['...'] | int   | None = '...'
    packet_loss:         Literal['...'] | float | None = '...'
    packet_errors:       Literal['...'] | int   | None = '...'
    rtt_min:             Literal['...'] | float | None = '...'
    rtt_avg:             Literal['...'] | float | None = '...'
    rtt_max:             Literal['...'] | float | None = '...'
    rtt_mdev:            Literal['...'] | float | None = '...'


@dataclass(kw_only=True, slots=True)
class PlayerUserIPDetection:
    time: str
    date_time: str

    as_processed_task: bool = True
    type: Literal['Static IP'] = 'Static IP'


@dataclass(kw_only=True, slots=True)
class PlayerModMenus:
    usernames: list[str] = dataclasses.field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]


class Player:  # pylint: disable=too-many-instance-attributes
    def __init__(self, *, ip: str, port: int, packet_datetime: datetime) -> None:
        self.left_event = Event()

        self.ip = ip
        self.rejoins = 0
        self.packets = 1
        self.total_packets = 1
        self.usernames: list[str] = []

        self.reverse_dns = PlayerReverseDNS()
        self.pps = PlayerPPS()
        self.ppm = PlayerPPM()
        self.ports = PlayerPorts.from_packet_port(port)
        self.datetime = PlayerDateTime.from_packet_datetime(packet_datetime)
        self.iplookup = PlayerIPLookup()
        self.ping = PlayerPing()

        self.country_flag: PlayerCountryFlag | None = None
        self.userip: UserIP | None = None
        self.userip_detection: PlayerUserIPDetection | None = None
        self.mod_menus: PlayerModMenus | None = None

    def mark_as_seen(self, *, port: int, packet_datetime: datetime) -> None:
        self.datetime.last_seen = packet_datetime
        self.total_packets += 1
        self.packets += 1
        self.pps.counter += 1
        self.ppm.counter += 1

        if port != self.ports.last:
            if port not in self.ports.all:
                self.ports.all.append(port)

            if port in self.ports.middle:
                self.ports.middle.remove(port)

            if self.ports.last not in self.ports.middle and self.ports.last != self.ports.first:
                self.ports.middle.append(self.ports.last)

            self.ports.last = port

    def mark_as_rejoined(self, *, port: int, packet_datetime: datetime) -> None:
        self.left_event.clear()
        self.datetime.last_rejoin = packet_datetime
        self.packets = 1
        self.pps.counter = 1
        self.ppm.counter = 1
        self.rejoins += 1
        self.total_packets += 1

        if Settings.GUI_RESET_PORTS_ON_REJOINS:
            self.ports.reset(port)

    def mark_as_left(self) -> None:
        self.left_event.set()
        self.pps.reset()
        self.ppm.reset()

        PlayersRegistry.move_player_to_disconnected(self)

        # Clear IP from warning sets so detections will trigger again on rejoin
        MobileWarnings.remove_notified_ip(self.ip)
        VPNWarnings.remove_notified_ip(self.ip)
        HostingWarnings.remove_notified_ip(self.ip)

        if self.userip_detection and self.userip_detection.as_processed_task:
            self.userip_detection.as_processed_task = False
            Thread(
                target=process_userip_task,
                name=f'ProcessUserIPTask-{self.ip}-disconnected',
                args=(self, 'disconnected'), daemon=True,
            ).start()


class PlayersRegistry:
    """Class to manage the registry of connected and disconnected players.

    This class provides methods to add, retrieve, and iterate over players in the registry.
    """
    _DEFAULT_CONNECTED_SORT_ORDER   : ClassVar = 'datetime.last_rejoin'
    _DEFAULT_DISCONNECTED_SORT_ORDER: ClassVar = 'datetime.last_seen'

    _registry_lock: ClassVar = RLock()
    _connected_players_registry   : ClassVar[dict[str, Player]] = {}
    _disconnected_players_registry: ClassVar[dict[str, Player]] = {}

    @classmethod
    def _get_sorted_connected_players(cls) -> list[Player]:
        return sorted(
            cls._connected_players_registry.values(),
            key=attrgetter(cls._DEFAULT_CONNECTED_SORT_ORDER),
        )

    @classmethod
    def _get_sorted_disconnected_players(cls) -> list[Player]:
        return sorted(
            cls._disconnected_players_registry.values(),
            key=attrgetter(cls._DEFAULT_DISCONNECTED_SORT_ORDER),
            reverse=True,
        )

    @classmethod
    def add_connected_player(cls, player: Player) -> Player:
        """Add a connected player to the registry.

        Args:
            player (Player): The player object to add.

        Returns:
            Player: The player object that was added.

        Raies:
            PlayerAlreadyExistsError: If the player already exists in the registry.
        """
        with cls._registry_lock:
            if player.ip in cls._connected_players_registry:
                raise PlayerAlreadyExistsError(player.ip)

            cls._connected_players_registry[player.ip] = player
            return player

    @classmethod
    def move_player_to_connected(cls, player: Player) -> None:
        """Move a player from the disconnected registry to the connected registry.

        Args:
            player (Player): The player object to move.

        Raises:
            PlayerNotFoundError: If the player is not found in the disconnected registry.
        """
        with cls._registry_lock:
            if player.ip not in cls._disconnected_players_registry:
                raise PlayerNotFoundInRegistryError(player.ip)

            cls._connected_players_registry[player.ip] = cls._disconnected_players_registry.pop(player.ip)

    @classmethod
    def move_player_to_disconnected(cls, player: Player) -> None:
        """Move a player from the connected registry to the disconnected registry.

        Args:
            player (Player): The player object to move.

        Raises:
            PlayerNotFoundError: If the player is not found in the connected registry.
        """
        with cls._registry_lock:
            if player.ip not in cls._connected_players_registry:
                raise PlayerNotFoundInRegistryError(player.ip)

            cls._disconnected_players_registry[player.ip] = cls._connected_players_registry.pop(player.ip)

    @classmethod
    def get_player_by_ip(cls, ip: str, /) -> Player | None:
        """Get a player by their IP address.

        Args:
            ip (str): The IP address of the player.

        Returns:
            The player object if found, otherwise `None`.
        """
        with cls._registry_lock:
            return cls._connected_players_registry.get(ip) or cls._disconnected_players_registry.get(ip)

    @classmethod
    def require_player_by_ip(cls, ip: str, /) -> Player:
        """Get a player by IP, raise if not found.

        Args:
            ip (str): The IP address of the player.

        Returns:
            Player: The player object.

        Raises:
            PlayerNotFoundInRegistryError: If no player exists for the given IP.
        """
        player = cls.get_player_by_ip(ip)
        if player is None:
            raise PlayerNotFoundInRegistryError(ip)
        return player

    @classmethod
    def get_default_sorted_players(
        cls,
        *,
        include_connected: bool = True,
        include_disconnected: bool = True,
    ) -> list[Player]:
        """Return a snapshot of players sorted by default criteria.

        Connected players are sorted by last rejoin (ascending),
        disconnected players by last seen (descending).
        """
        with cls._registry_lock:
            players: list[Player] = []
            if include_connected:
                players.extend(cls._get_sorted_connected_players())
            if include_disconnected:
                players.extend(cls._get_sorted_disconnected_players())
            return players

    @classmethod
    def get_default_sorted_connected_and_disconnected_players(cls) -> tuple[list[Player], list[Player]]:
        """Return connected and disconnected players, each sorted by their default criteria."""
        with cls._registry_lock:
            return (
                cls._get_sorted_connected_players(),
                cls._get_sorted_disconnected_players(),
            )


class SessionHost:
    player: ClassVar[Player | None] = None
    search_player: ClassVar[bool] = False
    players_pending_for_disconnection: ClassVar[list[Player]] = []

    @staticmethod
    def get_host_player(session_connected: list[Player]) -> Player | None:
        from modules.constants.standalone import MINIMUM_PACKETS_FOR_SESSION_HOST
        from modules.utils import take

        connected_players = take(2, sorted(session_connected, key=attrgetter('datetime.last_rejoin')))

        potential_session_host_player = None

        if len(connected_players) == 1:
            potential_session_host_player = connected_players[0]
        elif len(connected_players) == 2:  # noqa: PLR2004
            time_difference = connected_players[1].datetime.last_rejoin - connected_players[0].datetime.last_rejoin
            if time_difference >= timedelta(milliseconds=200):
                potential_session_host_player = connected_players[0]
        else:
            raise UnexpectedPlayerCountError(len(connected_players))

        if (
            not potential_session_host_player
            # Skip players remaining to be disconnected from the previous session.
            or potential_session_host_player in SessionHost.players_pending_for_disconnection
            # The lower this value, the riskier it becomes, as it could potentially flag a player who ultimately isn't part of the newly discovered session.
            # In such scenarios, a better approach might involve checking around 25-100 packets.
            # However, increasing this value also increases the risk, as the host may have already disconnected.
            or potential_session_host_player.packets < MINIMUM_PACKETS_FOR_SESSION_HOST
        ):
            return None

        SessionHost.player = potential_session_host_player
        SessionHost.search_player = False
        return potential_session_host_player


@dataclass(frozen=True, config={'arbitrary_types_allowed': True}, slots=True)
class UserIPSettings:  # pylint: disable=too-many-instance-attributes,invalid-name
    """Class to represent settings with attributes for each setting key."""
    ENABLED: bool
    COLOR: QColor
    LOG: bool
    NOTIFICATIONS: bool
    VOICE_NOTIFICATIONS: Literal['Male', 'Female', False]
    PROTECTION: Literal['Suspend_Process', 'Exit_Process', 'Restart_Process', 'Shutdown_PC', 'Restart_PC', False]
    PROTECTION_PROCESS_PATH: Path | None
    PROTECTION_RESTART_PROCESS_PATH: Path | None
    PROTECTION_SUSPEND_PROCESS_MODE: int | float | Literal['Auto', 'Manual']


@dataclass(frozen=True, slots=True)
class UserIP:
    """Class representing information associated with a specific IP, including settings and usernames."""
    ip: str
    database_path: Path
    settings: UserIPSettings
    usernames: list[str]


class UserIPDatabases:
    _update_userip_database_lock: ClassVar = Lock()

    userip_databases: ClassVar[list[tuple[Path, UserIPSettings, dict[str, list[str]]]]] = []
    ips_set: ClassVar[set[str]] = set()
    notified_settings_corrupted: ClassVar[set[Path]] = set()
    notified_ip_invalid: ClassVar[set[str]] = set()
    notified_ip_conflicts: ClassVar[set[str]] = set()

    @staticmethod
    def _notify_ip_conflict(
        *,
        initial_userip_database: Path,
        initial_userip_usernames: list[str],
        initial_userip_ip: str,
        conflicting_userip_database: Path,
        conflicting_userip_username: str,
        conflicting_userip_ip: str,
    ):
        from modules.constants.standard import USERIP_DATABASES_PATH

        Thread(
            target=MsgBox.show,
            name=f'UserIPConflictError-{initial_userip_ip}',
            kwargs={
                'title': TITLE,
                'text': format_triple_quoted_text(f"""
                    ERROR:
                        UserIP databases IP conflict

                    INFOS:
                        The same IP cannot be assigned to multiple
                        databases.
                        Users assigned to this IP will be ignored until
                        the conflict is resolved.

                    DEBUG:
                        "{initial_userip_database.relative_to(USERIP_DATABASES_PATH).with_suffix("")}":
                        {', '.join(initial_userip_usernames)}={initial_userip_ip}

                        "{conflicting_userip_database.relative_to(USERIP_DATABASES_PATH).with_suffix("")}":
                        {conflicting_userip_username}={conflicting_userip_ip}
                """),
                'style': MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SYSTEMMODAL,
            },
            daemon=True,
        ).start()

    @classmethod
    def populate(cls, database_entries: list[tuple[Path, UserIPSettings, dict[str, list[str]]]]) -> None:
        """Replace `cls.userip_databases` with a new set of databases.

        Args:
            database_entries: A list of tuples containing database_path, settings, and user_ips.
        """
        with cls._update_userip_database_lock:
            cls.userip_databases = [
                (database_path, settings, user_ips)
                for database_path, settings, user_ips in database_entries
                if settings.ENABLED
            ]

    @classmethod
    def build(cls) -> None:
        """Build the userip_infos_by_ip dictionary dynamically from the current databases.

        This method updates the dictionaries without clearing their content entirely and avoids duplicates.
        """
        with cls._update_userip_database_lock:
            ips_set: set[str] = set()
            ip_to_userip: dict[str, UserIP] = {}
            unresolved_conflicts: set[str] = set()

            for database_path, settings, user_ips in cls.userip_databases:
                for username, ips in user_ips.items():
                    for ip in ips:
                        # If the IP is already assigned to a different database, it's a conflict.
                        if ip in ip_to_userip and ip_to_userip[ip].database_path != database_path:
                            if ip not in cls.notified_ip_conflicts:
                                cls._notify_ip_conflict(
                                    initial_userip_database=ip_to_userip[ip].database_path,
                                    initial_userip_usernames=ip_to_userip[ip].usernames,
                                    initial_userip_ip=ip_to_userip[ip].ip,
                                    conflicting_userip_database=database_path,
                                    conflicting_userip_username=username,
                                    conflicting_userip_ip=ip,
                                )
                                cls.notified_ip_conflicts.add(ip)
                            unresolved_conflicts.add(ip)
                            continue

                        ips_set.add(ip)

                        # If it's a new entry, add it
                        if ip not in ip_to_userip:
                            ip_to_userip[ip] = UserIP(
                                ip=ip,
                                database_path=database_path,
                                settings=settings,
                                usernames=[username],
                            )
                        elif username not in ip_to_userip[ip].usernames:  # Append username if it doesn't already exist
                            ip_to_userip[ip].usernames.append(username)

                        # Assign the UserIP object to the PlayerRegistry if applicable
                        if player := PlayersRegistry.get_player_by_ip(ip):
                            player.userip = ip_to_userip[ip]

            # Remove resolved conflicts
            resolved_conflicts = cls.notified_ip_conflicts - unresolved_conflicts
            for resolved_ip in resolved_conflicts:
                cls.notified_ip_conflicts.remove(resolved_ip)

            cls.ips_set = ips_set

    @classmethod
    def get_userip_database_filepaths(cls) -> list[Path]:
        with cls._update_userip_database_lock:
            return [database_path for database_path, _, _ in cls.userip_databases]


# Detection warning tracking systems
class MobileWarnings:
    lock: ClassVar = Lock()
    notified_mobile_ips: ClassVar[set[str]] = set()

    @classmethod
    def add_notified_ip(cls, ip: str) -> bool:
        """Add an IP to the notified mobile IPs set in a thread-safe manner.

        Args:
            ip: The IP address to add

        Returns:
            bool: `True` if the IP was newly added, `False` if it was already present
        """
        with cls.lock:
            if ip in cls.notified_mobile_ips:
                return False
            cls.notified_mobile_ips.add(ip)
            return True

    @classmethod
    def is_ip_notified(cls, ip: str) -> bool:
        """Check if an IP has already been notified for mobile detection.

        Args:
            ip: The IP address to check

        Returns:
            bool: `True` if the IP has been notified, `False` otherwise
        """
        with cls.lock:
            return ip in cls.notified_mobile_ips

    @classmethod
    def remove_notified_ip(cls, ip: str) -> bool:
        """Remove an IP from the notified mobile IPs set in a thread-safe manner.

        Args:
            ip: The IP address to remove

        Returns:
            bool: `True` if the IP was removed, `False` if it wasn't present
        """
        with cls.lock:
            if ip in cls.notified_mobile_ips:
                cls.notified_mobile_ips.remove(ip)
                return True
            return False

    @classmethod
    def clear_all_notified_ips(cls) -> None:
        """Clear all notified mobile IPs in a thread-safe manner."""
        with cls.lock:
            cls.notified_mobile_ips.clear()

    @classmethod
    def get_notified_ips_count(cls) -> int:
        """Get the count of notified mobile IPs in a thread-safe manner.

        Returns:
            The number of notified mobile IPs
        """
        with cls.lock:
            return len(cls.notified_mobile_ips)

    @classmethod
    def get_notified_ips_copy(cls) -> set[str]:
        """Get a copy of the notified mobile IPs set in a thread-safe manner.

        Returns:
            A copy of the notified mobile IPs set
        """
        with cls.lock:
            return cls.notified_mobile_ips.copy()


class VPNWarnings:
    lock: ClassVar = Lock()
    notified_vpn_ips: ClassVar[set[str]] = set()

    @classmethod
    def add_notified_ip(cls, ip: str) -> bool:
        """Add an IP to the notified VPN IPs set in a thread-safe manner.

        Args:
            ip: The IP address to add

        Returns:
            bool: `True` if the IP was newly added, `False` if it was already present
        """
        with cls.lock:
            if ip in cls.notified_vpn_ips:
                return False
            cls.notified_vpn_ips.add(ip)
            return True

    @classmethod
    def is_ip_notified(cls, ip: str) -> bool:
        """Check if an IP has already been notified for VPN detection.

        Args:
            ip: The IP address to check

        Returns:
            bool: `True` if the IP has been notified, `False` otherwise
        """
        with cls.lock:
            return ip in cls.notified_vpn_ips

    @classmethod
    def remove_notified_ip(cls, ip: str) -> bool:
        """Remove an IP from the notified VPN IPs set in a thread-safe manner.

        Args:
            ip: The IP address to remove

        Returns:
            bool: `True` if the IP was removed, `False` if it wasn't present
        """
        with cls.lock:
            if ip in cls.notified_vpn_ips:
                cls.notified_vpn_ips.remove(ip)
                return True
            return False

    @classmethod
    def clear_all_notified_ips(cls) -> None:
        """Clear all notified VPN IPs in a thread-safe manner."""
        with cls.lock:
            cls.notified_vpn_ips.clear()

    @classmethod
    def get_notified_ips_count(cls) -> int:
        """Get the count of notified VPN IPs in a thread-safe manner.

        Returns:
            The number of notified VPN IPs
        """
        with cls.lock:
            return len(cls.notified_vpn_ips)

    @classmethod
    def get_notified_ips_copy(cls) -> set[str]:
        """Get a copy of the notified VPN IPs set in a thread-safe manner.

        Returns:
            A copy of the notified VPN IPs set
        """
        with cls.lock:
            return cls.notified_vpn_ips.copy()


class HostingWarnings:
    lock: ClassVar = Lock()
    notified_hosting_ips: ClassVar[set[str]] = set()

    @classmethod
    def add_notified_ip(cls, ip: str) -> bool:
        """Add an IP to the notified hosting IPs set in a thread-safe manner.

        Args:
            ip: The IP address to add

        Returns:
            bool: `True` if the IP was newly added, `False` if it was already present
        """
        with cls.lock:
            if ip in cls.notified_hosting_ips:
                return False
            cls.notified_hosting_ips.add(ip)
            return True

    @classmethod
    def is_ip_notified(cls, ip: str) -> bool:
        """Check if an IP has already been notified for hosting detection.

        Args:
            ip: The IP address to check

        Returns:
            bool: `True` if the IP has been notified, `False` otherwise
        """
        with cls.lock:
            return ip in cls.notified_hosting_ips

    @classmethod
    def remove_notified_ip(cls, ip: str) -> bool:
        """Remove an IP from the notified hosting IPs set in a thread-safe manner.

        Args:
            ip: The IP address to remove

        Returns:
            bool: `True` if the IP was removed, `False` if it wasn't present
        """
        with cls.lock:
            if ip in cls.notified_hosting_ips:
                cls.notified_hosting_ips.remove(ip)
                return True
            return False

    @classmethod
    def clear_all_notified_ips(cls) -> None:
        """Clear all notified hosting IPs in a thread-safe manner."""
        with cls.lock:
            cls.notified_hosting_ips.clear()

    @classmethod
    def get_notified_ips_count(cls) -> int:
        """Get the count of notified hosting IPs in a thread-safe manner.

        Returns:
            The number of notified hosting IPs
        """
        with cls.lock:
            return len(cls.notified_hosting_ips)

    @classmethod
    def get_notified_ips_copy(cls) -> set[str]:
        """Get a copy of the notified hosting IPs set in a thread-safe manner.

        Returns:
            A copy of the notified hosting IPs set
        """
        with cls.lock:
            return cls.notified_hosting_ips.copy()


class GUIDetectionSettings:
    """Runtime GUI detection settings that persist during application execution but are not saved to settings file."""
    mobile_detection_enabled: ClassVar[bool] = False
    vpn_detection_enabled: ClassVar[bool] = False
    hosting_detection_enabled: ClassVar[bool] = False
    player_join_notifications_enabled: ClassVar[bool] = False
    player_leave_notifications_enabled: ClassVar[bool] = False


def check_for_updates() -> None:
    from modules.utils import format_project_version

    def get_updater_json_response() -> dict[str, Any] | None:
        from modules.constants.standalone import GITHUB_VERSIONS_URL

        while True:
            try:
                response = s.get(GITHUB_VERSIONS_URL)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                choice = MsgBox.show(
                    title=TITLE,
                    text=format_triple_quoted_text(f"""
                        ERROR:
                            Failed to check for updates.

                            DEBUG:
                                Exception: {type(e).__name__}
                                HTTP Code: {f"{e.response.status_code} - {e.response.reason}" if e.response else "No response"}

                        Please check your internet connection and ensure you have access to:
                        {GITHUB_VERSIONS_URL}

                        Abort:
                            Exit and open the "{TITLE}" GitHub page to
                            download the latest version.
                        Retry:
                            Try checking for updates again.
                        Ignore:
                            Continue using the current version (not recommended).
                    """),
                    style=MsgBox.Style.MB_ABORTRETRYIGNORE | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND,
                )

                if choice == MsgBox.ReturnValues.IDABORT:
                    webbrowser.open(GITHUB_RELEASES_URL)
                    sys.exit(0)
                elif choice == MsgBox.ReturnValues.IDIGNORE:
                    return None
            else:
                versions_json = response.json()
                if not isinstance(versions_json, dict):
                    raise TypeError(format_type_error(versions_json, dict))

                return versions_json  # pyright: ignore[reportUnknownVariableType]

    versions_json = get_updater_json_response()
    if versions_json is None:
        return

    current_version = Version(PYPROJECT_DATA['project']['version'])

    # Get versions from the response
    latest_stable_version = Version(versions_json['latest_stable']['version'])
    latest_rc_version = Version(versions_json['latest_prerelease']['version'])

    # Check for updates based on the current version
    is_new_stable_version_available = latest_stable_version > current_version
    is_new_rc_version_available = latest_rc_version > current_version

    # Determine which version to display based on the user's channel setting
    if is_new_stable_version_available or (Settings.UPDATER_CHANNEL == 'RC' and is_new_rc_version_available):
        update_channel = 'pre-release' if (Settings.UPDATER_CHANNEL == 'RC' and is_new_rc_version_available) else 'stable release'
        latest_version = latest_rc_version if (Settings.UPDATER_CHANNEL == 'RC' and is_new_rc_version_available) else latest_stable_version

        if MsgBox.show(
            title=TITLE,
            text=format_triple_quoted_text(f"""
                New {update_channel} version found. Do you want to update?

                Current version: {format_project_version(current_version)}
                Latest version: {format_project_version(latest_version)}
            """),
            style=MsgBox.Style.MB_YESNO | MsgBox.Style.MB_ICONQUESTION | MsgBox.Style.MB_SETFOREGROUND,
        ) == MsgBox.ReturnValues.IDYES:
            webbrowser.open(GITHUB_RELEASES_URL)
            sys.exit(0)


def populate_network_interfaces_info() -> None:
    """Populate the AllInterfaces collection with network interface details."""
    from modules.networking.wmi_utils import (
        iterate_project_legacy_network_adapter_details,
        iterate_project_legacy_network_ip_details,
        iterate_project_network_adapter_details,
        iterate_project_network_ip_details,
        iterate_project_network_neighbor_details,
    )

    def validate_and_format_mac_address(mac_address: str | None) -> str | None:
        """Validate the MAC address, ensuring it is in the correct format."""
        if mac_address in (None, ''):
            return None

        formatted_mac_address = format_mac_address(mac_address)
        if not is_mac_address(formatted_mac_address):
            stdout_crash_text = format_triple_quoted_text(f"""
                ERROR:
                    Developer didn't expect this scenario to be possible.

                INFOS:
                    The value does not appear to be a valid MAC address.

                DEBUG:
                    mac_address={mac_address}
                    formatted_mac_address={formatted_mac_address}
            """)
            terminate_script('EXIT', stdout_crash_text, stdout_crash_text)

        return formatted_mac_address

    def validate_ip_address(ip_address: str | None) -> str | None:
        """Validate the IP address, ensuring it is a valid IPv4 address."""
        if ip_address in (None, ''):
            return None

        if not is_ipv4_address(ip_address):
            stdout_crash_text = format_triple_quoted_text(f"""
                ERROR:
                    Developer didn't expect this scenario to be possible.

                INFOS:
                    The value does not appear to be a valid IPv4 address.

                DEBUG:
                    ip_address={ip_address}
            """)
            terminate_script('EXIT', stdout_crash_text, stdout_crash_text)

        return ip_address

    def _populate_network_adapter_details() -> None:
        """Populate AllInterfaces collection with network adapter details from MSFT_NetAdapter."""
        for interface_index, name, interface_description, state in iterate_project_network_adapter_details():
            interface = AllInterfaces.get_interface(interface_index)
            if not interface:
                AllInterfaces.add_interface(Interface(
                    index=interface_index,
                    state=state,
                    name=name,
                    descriptions=[interface_description] if interface_description is not None else [],
                ))
                continue

            interface.update_state(state)
            interface.update_name(name)
            interface.add_description(interface_description)

    def _populate_legacy_network_adapter_details() -> None:
        """Populate AllInterfaces collection with legacy network adapter details."""
        for interface_index, net_connection_id, description, mac_address, manufacturer in iterate_project_legacy_network_adapter_details():
            validated_and_formatted_mac_address = validate_and_format_mac_address(mac_address)

            interface = AllInterfaces.get_interface(interface_index)
            if not interface:
                AllInterfaces.add_interface(Interface(
                    index=interface_index,
                    name=net_connection_id,
                    mac_address=validated_and_formatted_mac_address,
                    manufacturer=manufacturer,
                    descriptions=[description] if description is not None else [],
                ))
                continue

            interface.update_name(net_connection_id)
            interface.update_mac_address(validated_and_formatted_mac_address)
            interface.update_manufacturer(manufacturer)
            interface.add_description(description)

    def _populate_network_ip_details() -> None:
        """Populate AllInterfaces collection with network IP address details."""
        for interface_index, interface_alias, ipv4_address in iterate_project_network_ip_details():
            validated_ip_address = validate_ip_address(ipv4_address)

            interface = AllInterfaces.get_interface(interface_index)
            if not interface:
                AllInterfaces.add_interface(Interface(
                    index=interface_index,
                    name=interface_alias,
                    ip_addresses=[validated_ip_address] if validated_ip_address else [],
                ))
                continue

            interface.update_name(interface_alias)
            interface.add_ip_address(validated_ip_address)

    def _populate_legacy_network_ip_details() -> None:
        """Populate AllInterfaces collection with legacy network IP address details."""
        for interface_index, description, mac_address, ip_address, ip_enabled in iterate_project_legacy_network_ip_details():
            validated_ip_addresses = [
                validated_ip_address
                for ip in dedup_preserve_order(
                    [ip for ip in ip_address if is_ipv4_address(ip)]
                    if ip_address is not None else [],
                )
                if (validated_ip_address := validate_ip_address(ip))
            ]
            validated_and_formatted_mac_address = validate_and_format_mac_address(mac_address)

            interface = AllInterfaces.get_interface(interface_index)
            if not interface:
                AllInterfaces.add_interface(Interface(
                    index=interface_index,
                    ip_enabled=ip_enabled,
                    mac_address=validated_and_formatted_mac_address,
                    ip_addresses=validated_ip_addresses,
                    descriptions=[description] if description is not None else [],
                ))
                continue

            interface.update_ip_enabled(new_value=ip_enabled)
            interface.update_mac_address(validated_and_formatted_mac_address)
            interface.add_description(description)
            for ip in validated_ip_addresses:
                interface.add_ip_address(ip)

    def _update_network_io_stats() -> None:
        """Update network interface statistics like packets sent and received."""
        net_io_stats = psutil.net_io_counters(pernic=True)
        for interface_name, interface_stats in net_io_stats.items():
            interface = AllInterfaces.get_interface_by_name(interface_name)
            if not interface:
                continue

            interface.update_packets_sent(interface_stats.packets_sent)
            interface.update_packets_recv(interface_stats.packets_recv)

    def _populate_arp_cache_details() -> None:
        """Populate ARP cache information for each interface."""
        for interface_index, ip_address, mac_address in iterate_project_network_neighbor_details():
            interface = AllInterfaces.get_interface(interface_index)
            if not interface:
                continue

            validated_ip_address = validate_ip_address(ip_address)
            validated_and_formatted_mac_address = validate_and_format_mac_address(mac_address)

            if (
                validated_ip_address is None
                or validated_and_formatted_mac_address is None
                or validated_and_formatted_mac_address in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}  # Skip ARP entries with known placeholder MAC addresses
                or not is_valid_non_special_ipv4(validated_ip_address)
            ):
                continue

            interface.add_arp_entry(ARPEntry(
                ip_address=validated_ip_address,
                mac_address=validated_and_formatted_mac_address,
                organization_name=mac_lookup.get_mac_address_organization_name(validated_and_formatted_mac_address) or 'N/A',
            ))

    _populate_network_adapter_details()
    _populate_legacy_network_adapter_details()
    _populate_network_ip_details()
    _populate_legacy_network_ip_details()
    _update_network_io_stats()
    if Settings.CAPTURE_ARP:
        _populate_arp_cache_details()


def get_filtered_tshark_interfaces() -> list[tuple[int, str, str]]:
    """Retrieve a list of available TShark interfaces, excluding a list of exclusions.

    Returns:
        A list of tuples containing:
        - Index (int)
        - Device name (str)
        - Interface name (str)
    """
    from modules.constants.standalone import (
        EXCLUDED_CAPTURE_NETWORK_INTERFACES,
        INTERFACE_PARTS_LENGTH,
    )

    def process_stdout(stdout_line: str) -> tuple[int, str, str]:
        parts = stdout_line.strip().split(' ', maxsplit=INTERFACE_PARTS_LENGTH - 1)

        if len(parts) != INTERFACE_PARTS_LENGTH:
            raise TSharkOutputParsingError(INTERFACE_PARTS_LENGTH, len(parts), stdout_line)

        index = int(parts[0].removesuffix('.'))
        device_name = parts[1]
        name = parts[2].removeprefix('(').removesuffix(')')

        return index, device_name, name

    tshark_output = subprocess.check_output([TSHARK_PATH, '-D'], encoding='utf-8', text=True)

    return [
        (index, device_name, name)
        for index, device_name, name in map(process_stdout, tshark_output.splitlines())
        if name not in EXCLUDED_CAPTURE_NETWORK_INTERFACES
    ]


def select_interface(interfaces_selection_data: list[InterfaceSelectionData], screen_width: int, screen_height: int) -> InterfaceSelectionData:
    """Select the best matching interface based on given settings.

    If no interface matches, show the selection dialog to prompt the user.
    """

    def select_best_settings_matching_interface() -> InterfaceSelectionData | None:
        """Select the interface with the highest priority based on the given settings.

        Returns None if no interface matches.
        """

        def calculate_interface_priority(interface: InterfaceSelectionData) -> int:
            """Calculate the priority of an interface based on the given settings.

            Priority increases for each matching setting.
            """
            priority = 0

            if Settings.CAPTURE_INTERFACE_NAME is not None and interface.name == Settings.CAPTURE_INTERFACE_NAME:
                priority += 1
            if Settings.CAPTURE_MAC_ADDRESS is not None and interface.mac_address == Settings.CAPTURE_MAC_ADDRESS:
                priority += 1
            if Settings.CAPTURE_IP_ADDRESS is not None and interface.ip_address == Settings.CAPTURE_IP_ADDRESS:
                priority += 1

            return priority

        # First, try to select the best matching interface based on priority
        max_priority = 0
        selected_interface_index = None

        for interface in interfaces_selection_data:
            priority = calculate_interface_priority(interface)

            if priority == max_priority:
                selected_interface_index = None  # If multiple matches found, reset selection
            elif priority > max_priority:
                max_priority = priority
                selected_interface_index = interface.selection_index

        if selected_interface_index is not None:
            return interfaces_selection_data[selected_interface_index]

        return None

    # First try to select the best matching interface based on settings
    if (
        # Check if the network interface prompt is disabled
        not Settings.CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT
        # Check if any capture setting is defined
        and any(setting is not None for setting in (Settings.CAPTURE_INTERFACE_NAME, Settings.CAPTURE_MAC_ADDRESS, Settings.CAPTURE_IP_ADDRESS))
    ):
        selected_interface = select_best_settings_matching_interface()
        if selected_interface is not None:
            return selected_interface

    # If no suitable interface was found, prompt the user to select an interface
    selected_interface = show_interface_selection_dialog(screen_width, screen_height, interfaces_selection_data)
    if selected_interface is None:
        sys.exit(0)  # Exit if no selection is made

    return selected_interface


def update_and_initialize_geolite2_readers() -> tuple[bool, geoip2.database.Reader | None, geoip2.database.Reader | None, geoip2.database.Reader | None]:
    def update_geolite2_databases() -> dict[str, requests.exceptions.RequestException | str | int | None]:
        from modules.constants.standalone import (  # TODO(BUZZARDGTA): Implement adding: `, GITHUB_RELEASE_API__GEOLITE2__BACKUP__URL` in case the first one fails.
            ERROR_USER_MAPPED_FILE,
            GITHUB_RELEASE_API__GEOLITE2__URL,
        )
        from modules.constants.standard import GEOLITE2_DATABASES_FOLDER_PATH

        geolite2_version_file_path = GEOLITE2_DATABASES_FOLDER_PATH / 'version.json'
        geolite2_databases: dict[str, dict[str, str | None]] = {
            f'GeoLite2-{db}.mmdb': {
                'current_version': None,
                'last_version': None,
                'download_url': None,
            }
            for db in ('ASN', 'City', 'Country')
        }

        try:
            with geolite2_version_file_path.open('r', encoding='utf-8') as f:
                loaded_data = json.load(f)
        except FileNotFoundError:
            pass
        else:
            if isinstance(loaded_data, dict):
                for database_name, database_info in loaded_data.items():  # pyright: ignore[reportUnknownVariableType]
                    if not isinstance(database_name, str):
                        continue
                    if not isinstance(database_info, dict):
                        continue
                    if database_name not in geolite2_databases:
                        continue

                    geolite2_databases[database_name]['current_version'] = database_info.get('version', None)  # pyright: ignore[reportUnknownMemberType]

        try:
            response = s.get(GITHUB_RELEASE_API__GEOLITE2__URL)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            return {
                'exception': e,
                'url': GITHUB_RELEASE_API__GEOLITE2__URL,
                'http_code': getattr(e.response, 'status_code', None),
            }

        release_data = response.json()
        if not isinstance(release_data, dict):
            raise TypeError(format_type_error(release_data, dict))

        for asset in release_data['assets']:  # pyright: ignore[reportUnknownVariableType]
            asset_name = asset['name']  # pyright: ignore[reportUnknownVariableType]
            if not isinstance(asset_name, str):
                continue
            if asset_name not in geolite2_databases:
                continue

            geolite2_databases[asset_name].update({
                'last_version': asset['updated_at'],  # pyright: ignore[reportUnknownArgumentType]
                'download_url': asset['browser_download_url'],  # pyright: ignore[reportUnknownArgumentType]
            })

        failed_fetching_flag_list: list[str] = []
        for database_name, database_info in geolite2_databases.items():
            if database_info['last_version']:
                if database_info['current_version'] != database_info['last_version']:
                    download_url = database_info['download_url']
                    if download_url is None:
                        failed_fetching_flag_list.append(database_name)
                        continue
                    try:
                        response = s.get(download_url)
                        response.raise_for_status()
                    except requests.exceptions.RequestException as e:
                        return {
                            'exception': e,
                            'url': download_url,
                            'http_code': getattr(e.response, 'status_code', None),
                        }

                    if not isinstance(response.content, bytes):
                        raise TypeError(format_type_error(response.content, bytes))

                    GEOLITE2_DATABASES_FOLDER_PATH.mkdir(parents=True, exist_ok=True)  # Create directory if it doesn't exist
                    destination_file_path = GEOLITE2_DATABASES_FOLDER_PATH / database_name

                    # [Bug-Fix]: https://github.com/BUZZARDGTA/Session-Sniffer/issues/28
                    if destination_file_path.is_file():
                        if hashlib.sha256(destination_file_path.read_bytes()).hexdigest() == hashlib.sha256(response.content).hexdigest():
                            geolite2_databases[database_name]['current_version'] = database_info['last_version']
                        else:
                            temp_path = Path(tempfile.gettempdir()) / database_name
                            temp_path.write_bytes(response.content)

                            try:
                                shutil.move(temp_path, destination_file_path)
                            except OSError as e:
                                # The file is currently open and in use by another process. Abort updating this database.
                                if e.winerror == ERROR_USER_MAPPED_FILE:
                                    if temp_path.is_file():
                                        temp_path.unlink()
                                    geolite2_databases[database_name]['current_version'] = database_info['current_version']
                    else:
                        destination_file_path.write_bytes(response.content)
                        geolite2_databases[database_name]['current_version'] = database_info['last_version']
            else:
                failed_fetching_flag_list.append(database_name)

        if failed_fetching_flag_list:
            Thread(
                target=MsgBox.show,
                name='GeoLite2DownloadError',
                kwargs={
                    'title': TITLE,
                    'text': format_triple_quoted_text(f"""
                        ERROR:
                            Failed fetching MaxMind GeoLite2 "{'", "'.join(failed_fetching_flag_list)}" database{pluralize(len(failed_fetching_flag_list))}.

                        DEBUG:
                            GITHUB_RELEASE_API__GEOLITE2__URL={GITHUB_RELEASE_API__GEOLITE2__URL}
                            failed_fetching_flag_list={failed_fetching_flag_list}

                        These MaxMind GeoLite2 database{pluralize(len(failed_fetching_flag_list))} will not be updated.
                    """),
                    'style': MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SYSTEMMODAL,
                },
                daemon=True,
            ).start()

        # Create the data dictionary, where each name maps to its version info
        data = {
            name: {'version': info['current_version']}
            for name, info in geolite2_databases.items()
        }

        # Convert the data to a JSON formatted string with proper indentation
        json_data = json.dumps(data, indent=4)

        # Write the JSON formatted string to the GeoLite2 version file
        geolite2_version_file_path.write_text(json_data, encoding='utf-8')

        return {
            'exception': None,
            'url': None,
            'http_code': None,
        }

    def initialize_geolite2_readers() -> tuple[geoip2.errors.GeoIP2Error | None, geoip2.database.Reader | None, geoip2.database.Reader | None, geoip2.database.Reader | None]:
        from modules.constants.standard import GEOLITE2_DATABASES_FOLDER_PATH

        try:
            geolite2_asn_reader = geoip2.database.Reader(GEOLITE2_DATABASES_FOLDER_PATH / 'GeoLite2-ASN.mmdb')
            geolite2_city_reader = geoip2.database.Reader(GEOLITE2_DATABASES_FOLDER_PATH / 'GeoLite2-City.mmdb')
            geolite2_country_reader = geoip2.database.Reader(GEOLITE2_DATABASES_FOLDER_PATH / 'GeoLite2-Country.mmdb')

            geolite2_asn_reader.asn('1.1.1.1')
            geolite2_city_reader.city('1.1.1.1')
            geolite2_country_reader.country('1.1.1.1')

            exception = None
        except geoip2.errors.GeoIP2Error as e:
            geolite2_asn_reader = None
            geolite2_city_reader = None
            geolite2_country_reader = None

            exception = e

        return exception, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader

    update_geolite2_databases__dict = update_geolite2_databases()
    exception__initialize_geolite2_readers, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = initialize_geolite2_readers()

    show_error = False
    msgbox_message = ''

    if update_geolite2_databases__dict['exception']:
        msgbox_message += f"Exception Error: {update_geolite2_databases__dict['exception']}\n\n"
        show_error = True
    if update_geolite2_databases__dict['url']:
        msgbox_message += f'Error: Failed fetching url: "{update_geolite2_databases__dict['url']}".'
        if update_geolite2_databases__dict['http_code']:
            msgbox_message += f" (http_code: {update_geolite2_databases__dict['http_code']})"
        msgbox_message += "\nImpossible to keep Maxmind's GeoLite2 IP to Country, City and ASN resolutions feature up-to-date.\n\n"
        show_error = True

    if exception__initialize_geolite2_readers:
        msgbox_message += f'Exception Error: {exception__initialize_geolite2_readers}\n\n'
        msgbox_message += "Now disabling MaxMind's GeoLite2 IP to Country, City and ASN resolutions feature.\n"
        msgbox_message += "Countrys, Citys and ASN from players won't shows up from the players fields."
        geoip2_enabled = False
        show_error = True
    else:
        geoip2_enabled = True

    if show_error:
        msgbox_title = TITLE
        msgbox_message = msgbox_message.rstrip('\n')
        msgbox_style = MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND
        MsgBox.show(msgbox_title, msgbox_message, msgbox_style)

    return geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader


colorama.init(autoreset=True)

SCRIPT_DIR = Path(sys.executable).parent if is_pyinstaller_compiled() else Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

if not is_pyinstaller_compiled():
    clear_screen()
    set_window_title(f'Checking that your Python packages versions matches with file "requirements.txt" - {TITLE}')
    print('\nChecking that your Python packages versions matches with file "requirements.txt" ...\n')

    if outdated_packages := check_packages_version(get_dependencies_from_pyproject() or get_dependencies_from_requirements()):
        msgbox_message = 'The following packages have version mismatches:\n\n'  # pylint: disable=invalid-name

        # Iterate over outdated packages and add each package's information to the message box text
        for package_name, required_version, installed_version in outdated_packages:
            msgbox_message += f'{package_name} (required {required_version}, installed {installed_version})\n'

        # Add additional message box text
        msgbox_message += f'\nKeeping your packages synced with "{TITLE}" ensures smooth script execution and prevents compatibility issues.'
        msgbox_message += '\n\nDo you want to ignore this warning and continue with script execution?'

        # Show message box
        msgbox_style = MsgBox.Style.MB_YESNO | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND
        msgbox_title = TITLE  # pylint: disable=invalid-name
        errorlevel = MsgBox.show(msgbox_title, msgbox_message, msgbox_style)
        if errorlevel != MsgBox.ReturnValues.IDYES:
            sys.exit(0)

clear_screen()
set_window_title(f'Applying your custom settings from "Settings.ini" - {TITLE}')
print('\nApplying your custom settings from "Settings.ini" ...\n')
Settings.load_from_settings_file(SETTINGS_PATH)

clear_screen()
set_window_title(f'Searching for a new update - {TITLE}')
print('\nSearching for a new update ...\n')
check_for_updates()

clear_screen()
set_window_title(f'Checking that "Npcap" driver is installed on your system - {TITLE}')
print('\nChecking that "Npcap" driver is installed on your system ...\n')
ensure_npcap_installed()

clear_screen()
set_window_title(f'Applying your custom settings from "Settings.ini" - {TITLE}')
print('\nApplying your custom settings from "Settings.ini" ...\n')
Settings.load_from_settings_file(SETTINGS_PATH)

clear_screen()
set_window_title(f"Initializing and updating MaxMind's GeoLite2 Country, City and ASN databases - {TITLE}")
print("\nInitializing and updating MaxMind's GeoLite2 Country, City and ASN databases ...\n")
geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = update_and_initialize_geolite2_readers()

clear_screen()
set_window_title(f'Initializing MacLookup module - {TITLE}')
print('\nInitializing MacLookup module ...\n')
mac_lookup = MacLookup(load_on_init=True)

clear_screen()
set_window_title(f'Capture network interface selection - {TITLE}')
print('\nCapture network interface selection ...\n')
populate_network_interfaces_info()

tshark_interfaces = [
    i for _, _, name in get_filtered_tshark_interfaces()
    if (i := AllInterfaces.get_interface_by_name(name)) and not i.is_interface_inactive()
]

screen_width, screen_height = get_screen_size()

interfaces_selection_data: list[InterfaceSelectionData] = []

for interface in tshark_interfaces:
    if (
        Settings.CAPTURE_INTERFACE_NAME is not None
        and interface.name is not None
        and interface.name.casefold() == Settings.CAPTURE_INTERFACE_NAME.casefold()
        and interface.name != Settings.CAPTURE_INTERFACE_NAME
    ):
        Settings.CAPTURE_INTERFACE_NAME = interface.name
        Settings.reconstruct_settings()

    manufacturer = 'N/A' if interface.manufacturer is None else interface.manufacturer
    packets_sent = 'N/A' if interface.packets_sent is None else interface.packets_sent
    packets_recv = 'N/A' if interface.packets_recv is None else interface.packets_recv
    interface_name = interface.name if interface.name is not None else 'Unknown Interface'

    if interface.ip_addresses:
        for ip_address in interface.ip_addresses:
            interfaces_selection_data.append(InterfaceSelectionData(len(interfaces_selection_data), interface_name, ', '.join(interface.descriptions), packets_sent, packets_recv, ip_address, interface.mac_address, manufacturer))
    else:
        interfaces_selection_data.append(InterfaceSelectionData(len(interfaces_selection_data), interface_name, ', '.join(interface.descriptions), packets_sent, packets_recv, 'N/A', interface.mac_address, manufacturer))

    if Settings.CAPTURE_ARP:
        for arp_entry in interface.get_arp_entries():
            organization_name = 'N/A' if arp_entry.organization_name is None else arp_entry.organization_name

            interfaces_selection_data.append(InterfaceSelectionData(len(interfaces_selection_data), interface_name, ', '.join(interface.descriptions), 'N/A', 'N/A', arp_entry.ip_address, arp_entry.mac_address, organization_name, is_arp=True))

selected_interface = select_interface(interfaces_selection_data, screen_width, screen_height)

clear_screen()
set_window_title(f'Initializing addresses and establishing connection to your PC / Console - {TITLE}')
print('\nInitializing addresses and establishing connection to your PC / Console ...\n')
need_rewrite_settings = False  # pylint: disable=invalid-name
fixed__capture_mac_address = selected_interface.mac_address
fixed__capture_ip_address = selected_interface.ip_address

if (
    Settings.CAPTURE_INTERFACE_NAME is None
    or selected_interface.name != Settings.CAPTURE_INTERFACE_NAME
):
    Settings.CAPTURE_INTERFACE_NAME = selected_interface.name
    need_rewrite_settings = True  # pylint: disable=invalid-name

if fixed__capture_mac_address != Settings.CAPTURE_MAC_ADDRESS:
    Settings.CAPTURE_MAC_ADDRESS = fixed__capture_mac_address
    need_rewrite_settings = True  # pylint: disable=invalid-name

if fixed__capture_ip_address != Settings.CAPTURE_IP_ADDRESS:
    Settings.CAPTURE_IP_ADDRESS = fixed__capture_ip_address
    need_rewrite_settings = True  # pylint: disable=invalid-name

if need_rewrite_settings:
    Settings.reconstruct_settings()

capture_filter: list[str] = ['ip', 'udp']
display_filter: list[str] = []
excluded_protocols: list[str] = []

if Settings.CAPTURE_IP_ADDRESS:
    capture_filter.append(f'((src host {Settings.CAPTURE_IP_ADDRESS} and (not (dst net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))) or (dst host {Settings.CAPTURE_IP_ADDRESS} and (not (src net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))))')

broadcast_support, multicast_support = check_broadcast_multicast_support(TSHARK_PATH, Settings.CAPTURE_INTERFACE_NAME)
if broadcast_support and multicast_support:
    capture_filter.append('not (broadcast or multicast)')
    vpn_mode_enabled = False  # pylint: disable=invalid-name
elif broadcast_support:
    capture_filter.append('not broadcast')
    vpn_mode_enabled = True  # pylint: disable=invalid-name
elif multicast_support:
    capture_filter.append('not multicast')
    vpn_mode_enabled = True  # pylint: disable=invalid-name
else:
    vpn_mode_enabled = True  # pylint: disable=invalid-name

capture_filter.append('not (portrange 0-1023 or port 5353)')

if Settings.CAPTURE_PROGRAM_PRESET:
    if Settings.CAPTURE_PROGRAM_PRESET == 'GTA5':
        capture_filter.append('(len >= 71 and len <= 1032)')
    elif Settings.CAPTURE_PROGRAM_PRESET == 'Minecraft':
        capture_filter.append('(len >= 49 and len <= 1498)')

    # If the <CAPTURE_PROGRAM_PRESET> setting is set, automatically blocks RTCP connections.
    # In case RTCP can be useful to get someone IP, I decided not to block them without using a <CAPTURE_PROGRAM_PRESET>.
    # RTCP is known to be for example the Discord's server IP while you are in a call there.
    # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
    # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
    # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
    # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
    excluded_protocols.append('rtcp')

if Settings.CAPTURE_BLOCK_THIRD_PARTY_SERVERS:
    capture_filter.append(f"not (net {' or '.join(ThirdPartyServers.get_all_ip_ranges())})")

    # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
    # But there can be a lot more, those are just a couples I could find on my own usage.
    excluded_protocols.extend(['ssdp', 'raknet', 'dtls', 'nbns', 'pcp', 'bt-dht', 'uaudp', 'classicstun', 'dhcp', 'mdns', 'llmnr'])

if excluded_protocols:
    display_filter.append(
        f"not ({' or '.join(excluded_protocols)})",
    )

if Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER:
    capture_filter.insert(0, f'({Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER})')

if Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER:
    display_filter.insert(0, f'({Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER})')

CAPTURE_FILTER = ' and '.join(capture_filter) if capture_filter else None
DISPLAY_FILTER = ' and '.join(display_filter) if display_filter else None

capture = PacketCapture(
    interface=Settings.CAPTURE_INTERFACE_NAME,
    tshark_path=TSHARK_PATH,
    capture_filter=CAPTURE_FILTER,
    display_filter=DISPLAY_FILTER,
)

gui_closed__event = Event()
_userip_logging_file_write_lock = Lock()


def wait_for_player_data_ready(player: Player, *, data_fields: tuple[Literal['userip.usernames', 'reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'], ...], timeout: float) -> bool:
    """Wait for specific player data fields to be ready for display.

    Args:
        player: The player object to wait for
        data_fields: Tuple of data field paths to wait for
        timeout: Maximum time to wait for data to be ready

    Returns:
        bool: `True` if all specified data is ready, `False` if timeout occurred
    """
    def check_userip_usernames(player: Player) -> bool:
        """Check if player has usernames in userip data."""
        return isinstance(player.userip, UserIP) and len(player.userip.usernames) > 0

    def check_reverse_dns_hostname(player: Player) -> bool:
        """Check if player reverse DNS is initialized."""
        return player.reverse_dns.is_initialized

    def check_iplookup_geolite2(player: Player) -> bool:
        """Check if player GeoLite2 data is initialized."""
        return player.iplookup.geolite2.is_initialized

    def check_iplookup_ipapi(player: Player) -> bool:
        """Check if player IP API data is initialized."""
        return player.iplookup.ipapi.is_initialized

    field_checkers = {
        'userip.usernames': check_userip_usernames,
        'reverse_dns.hostname': check_reverse_dns_hostname,
        'iplookup.geolite2': check_iplookup_geolite2,
        'iplookup.ipapi': check_iplookup_ipapi,
    }

    while not player.left_event.is_set() and (datetime.now(tz=LOCAL_TZ) - player.datetime.last_seen) < timedelta(seconds=timeout):
        if all(field_checkers[field](player) for field in data_fields if field in field_checkers):
            return True

        gui_closed__event.wait(0.1)

    return False


def show_detection_warning_popup(
    player: Player,
    notification_type: Literal['mobile', 'vpn', 'hosting', 'player_joined', 'player_left'],
) -> None:
    """Show a notification popup for detections or player connection events.

    Args:
        player: The player object with detection data
        notification_type: Type of notification - `mobile`, `vpn`, `hosting`, `player_joined`, or `player_left`
    """
    def show_popup_thread() -> None:
        """Thread function to show popup after ensuring data is ready."""
        notification_configs: dict[Literal['mobile', 'vpn', 'hosting', 'player_joined', 'player_left'], dict[Literal['emoji', 'title', 'description', 'icon', 'thread_name'], str | MsgBox.Style]] = {
            'mobile': {
                'emoji': '📱',
                'title': 'MOBILE CONNECTION DETECTED!',
                'description': 'A player using a mobile (cellular) connection has been detected in your session!',
                'icon': MsgBox.Style.MB_ICONINFORMATION,
                'thread_name': 'MobileWarning',
            },
            'vpn': {
                'emoji': '🚨',
                'title': 'VPN CONNECTION DETECTED!',
                'description': 'A player using a VPN/Proxy/Tor connection has been detected in your session!',
                'icon': MsgBox.Style.MB_ICONEXCLAMATION,
                'thread_name': 'VPNWarning',
            },
            'hosting': {
                'emoji': '🏢',
                'title': 'HOSTING CONNECTION DETECTED!',
                'description': 'A player connecting from a hosting provider or data center has been detected in your session!',
                'icon': MsgBox.Style.MB_ICONWARNING,
                'thread_name': 'HostingWarning',
            },
            'player_joined': {
                'emoji': '🟢',
                'title': 'PLAYER JOINED SESSION!',
                'description': 'A new player has joined your session!',
                'icon': MsgBox.Style.MB_ICONINFORMATION,
                'thread_name': 'PlayerJoined',
            },
            'player_left': {
                'emoji': '🔴',
                'title': 'PLAYER LEFT SESSION!',
                'description': 'A player has left your session!',
                'icon': MsgBox.Style.MB_ICONINFORMATION,
                'thread_name': 'PlayerLeft',
            },
        }

        config = notification_configs[notification_type]
        data_ready = wait_for_player_data_ready(player, data_fields=('reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'), timeout=3.0)
        time_label = 'Detection Time' if notification_type in {'mobile', 'vpn', 'hosting'} else 'Event Time'
        data_status_line = '' if data_ready else '⚠️ Some data may still be loading and missing from this notification\n\n'

        MsgBox.show(
            title=f"{TITLE} - {config['title']}",
            text=format_triple_quoted_text(f"""
                {config['emoji']} {config['title']} {config['emoji']}

                {config['description']}

                {data_status_line}############ PLAYER DETAILS ############
                Username{pluralize(len(player.usernames))}: {', '.join(player.usernames) or ""}
                {time_label}: {datetime.now(tz=LOCAL_TZ).strftime("%H:%M.%S")}

                ############ CONNECTION DETAILS ############
                IP Address: {player.ip}
                Hostname: {player.reverse_dns.hostname}
                Last Port: {player.ports.last}
                Middle Ports: {", ".join(map(str, reversed(player.ports.middle)))}
                First Port: {player.ports.first}
                Total Packets Exchanged: {player.total_packets}
                Current Session Packets: {player.packets}
                Rejoins: {player.rejoins}

                ############ LOCATION DETAILS ############
                Continent: {player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})
                Country: {player.iplookup.ipapi.country} ({player.iplookup.ipapi.country_code})
                Region: {player.iplookup.ipapi.region} ({player.iplookup.ipapi.region_code})

                ############ NETWORK DETAILS ############
                ISP: {player.iplookup.ipapi.isp}
                Organization: {player.iplookup.ipapi.org}
                ASN: {player.iplookup.ipapi.asn} ({player.iplookup.ipapi.as_name})

                ############ DETECTION FLAGS ############
                Mobile (cellular) connection: {player.iplookup.ipapi.mobile}
                Proxy, VPN or Tor exit address: {player.iplookup.ipapi.proxy}
                Hosting, colocated or data center: {player.iplookup.ipapi.hosting}
            """),
            style=MsgBox.Style.MB_OK | MsgBox.Style(config['icon']) | MsgBox.Style.MB_SYSTEMMODAL,
        )

    # Get thread name for the notification type
    notification_configs_for_thread_name = {
        'mobile': 'MobileWarning',
        'vpn': 'VPNWarning',
        'hosting': 'HostingWarning',
        'player_joined': 'PlayerJoined',
        'player_left': 'PlayerLeft',
    }

    Thread(
        target=show_popup_thread,
        name=f'{notification_configs_for_thread_name[notification_type]}-{player.ip}',
        daemon=True,
    ).start()


def process_userip_task(
    player: Player,
    connection_type: Literal['connected', 'disconnected'],
) -> None:
    with ThreadsExceptionHandler():
        from modules.constants.local import TTS_FOLDER_PATH
        from modules.constants.standard import SHUTDOWN_EXE, USERIP_LOGGING_PATH
        from modules.utils import (
            get_pid_by_path,
            terminate_process_tree,
            write_lines_to_file,
        )

        if player.userip_detection is None:
            raise TypeError(format_type_error(player.userip_detection, PlayerUserIPDetection))

        timeout = 10
        start_time = time.monotonic()

        while not isinstance(player.userip, UserIP):
            if time.monotonic() - start_time > timeout:
                raise TypeError(format_type_error(player.userip, UserIP))
            time.sleep(0.01)  # Sleep to prevent high CPU usage

        def suspend_process_for_duration_or_mode(process_pid: int, duration_or_mode: float | Literal['Auto', 'Manual']) -> None:
            """Suspends the specified process for a given duration or until a specified condition is met.

            Args:
                process_pid: The process ID of the process to be suspended.
                duration_or_mode: Specifies how long the process should be suspended.
                    - If a float, it defines the duration (in seconds) to suspend the process.
                    - If "Manual", the process remains suspended until manually resumed.
                    - If "Auto", the process resumes when the player is flagged as "disconnected".
            """
            process = psutil.Process(process_pid)
            process.suspend()

            if isinstance(duration_or_mode, (int, float)):
                gui_closed__event.wait(duration_or_mode)
                process.resume()
                return

            if duration_or_mode == 'Manual':
                return
            if duration_or_mode == 'Auto':
                while not player.left_event.is_set():
                    gui_closed__event.wait(0.1)
                process.resume()
                return

        # We wants to run this as fast as possible so it's on top of the function.
        if connection_type == 'connected' and player.userip.settings.PROTECTION:
            if player.userip.settings.PROTECTION == 'Suspend_Process' and isinstance(player.userip.settings.PROTECTION_PROCESS_PATH, Path):
                if process_pid := get_pid_by_path(player.userip.settings.PROTECTION_PROCESS_PATH):
                    Thread(
                        target=suspend_process_for_duration_or_mode,
                        name=f'UserIPSuspendProcess-{player.ip}',
                        args=(process_pid, player.userip.settings.PROTECTION_SUSPEND_PROCESS_MODE),
                        daemon=True,
                    ).start()

            elif player.userip.settings.PROTECTION in {'Exit_Process', 'Restart_Process'} and isinstance(player.userip.settings.PROTECTION_PROCESS_PATH, Path):
                if process_pid := get_pid_by_path(player.userip.settings.PROTECTION_PROCESS_PATH):
                    terminate_process_tree(process_pid)

                    if player.userip.settings.PROTECTION == 'Restart_Process' and isinstance(player.userip.settings.PROTECTION_RESTART_PROCESS_PATH, Path):
                        subprocess.Popen([str(player.userip.settings.PROTECTION_RESTART_PROCESS_PATH.absolute())])

            elif player.userip.settings.PROTECTION in {'Shutdown_PC', 'Restart_PC'}:
                validate_file(SHUTDOWN_EXE)

                subprocess.Popen([str(SHUTDOWN_EXE), '/s' if player.userip.settings.PROTECTION == 'Shutdown_PC' else '/r'])

        if player.userip.settings.VOICE_NOTIFICATIONS:
            if player.userip.settings.VOICE_NOTIFICATIONS == 'Male':
                voice_name = 'Liam'
            elif player.userip.settings.VOICE_NOTIFICATIONS == 'Female':
                voice_name = 'Jane'
            else:
                voice_name = None

            if not isinstance(voice_name, str):
                raise TypeError(format_type_error(voice_name, str))

            tts_file_path = TTS_FOLDER_PATH / f'{voice_name} ({connection_type}).wav'
            validate_file(tts_file_path)

            winsound.PlaySound(str(tts_file_path), winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)

        if connection_type == 'connected':
            from modules.constants.standard import USERIP_DATABASES_PATH

            wait_for_player_data_ready(player, data_fields=('userip.usernames', 'iplookup.geolite2'), timeout=10.0)

            relative_database_path = player.userip.database_path.relative_to(USERIP_DATABASES_PATH).with_suffix('')

            with _userip_logging_file_write_lock:
                write_lines_to_file(USERIP_LOGGING_PATH, 'a', [(
                    f'User{pluralize(len(player.userip.usernames))}: {", ".join(player.userip.usernames)} | '
                    f'IP:{player.ip} | Ports:{", ".join(map(str, reversed(player.ports.all)))} | '
                    f'Time:{player.userip_detection.date_time} | Country:{player.iplookup.geolite2.country} | '
                    f'Detection Type: {player.userip_detection.type} | '
                    f'Database:{relative_database_path}'
                )])

            if player.userip.settings.NOTIFICATIONS:
                wait_for_player_data_ready(player, data_fields=('userip.usernames', 'reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'), timeout=10.0)

                Thread(
                    target=MsgBox.show,
                    name=f'UserIPMsgBox-{player.ip}',
                    kwargs={
                        'title': TITLE,
                        'text': format_triple_quoted_text(f"""
                            #### UserIP detected at {player.userip_detection.time} ####
                            User{pluralize(len(player.userip.usernames))}: {', '.join(player.userip.usernames)}
                            IP Address: {player.ip}
                            Hostname: {player.reverse_dns.hostname}
                            Port{pluralize(len(player.ports.all))}: {', '.join(map(str, reversed(player.ports.all)))}
                            Country Code: {player.iplookup.geolite2.country_code}
                            Detection Type: {player.userip_detection.type}
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
                        """),
                        'style': MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SYSTEMMODAL,
                    },
                    daemon=True,
                ).start()


def iplookup_core() -> None:
    with ThreadsExceptionHandler():
        def throttle_until(requests_remaining: int, throttle_time: int) -> None:
            # Calculate sleep time only if there are remaining requests
            sleep_time = throttle_time / requests_remaining if requests_remaining > 0 else throttle_time

            # We sleep x seconds (just in case) to avoid triggering a "429" status code.
            gui_closed__event.wait(sleep_time)

        # Following values taken from https://ip-api.com/docs/api:batch the 03/04/2024.
        #MAX_REQUESTS = 15
        #MAX_THROTTLE_TIME = 60
        MAX_BATCH_IP_API_IPS = 100  # pylint: disable=invalid-name
        FIELDS_TO_LOOKUP = 'continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query'  # pylint: disable=invalid-name
        FIELD_MAPPINGS: dict[str, tuple[str, tuple[type[str | float | int | bool], ...]]] = {  # pylint: disable=invalid-name
            'continent': ('continent', (str,)),
            'continent_code': ('continentCode', (str,)),
            'country': ('country', (str,)),
            'country_code': ('countryCode', (str,)),
            'region': ('regionName', (str,)),
            'region_code': ('region', (str,)),
            'city': ('city', (str,)),
            'district': ('district', (str,)),
            'zip_code': ('zip', (str,)),
            'lat': ('lat', (float, int)),
            'lon': ('lon', (float, int)),
            'time_zone': ('timezone', (str,)),
            'offset': ('offset', (int,)),
            'currency': ('currency', (str,)),
            'isp': ('isp', (str,)),
            'org': ('org', (str,)),
            'asn': ('as', (str,)),
            'as_name': ('asname', (str,)),
            'mobile': ('mobile', (bool,)),
            'proxy': ('proxy', (bool,)),
            'hosting': ('hosting', (bool,)),
        }

        def validate_and_get_iplookup_field(
            player_ip: str,
            iplookup: dict[str, Any],
            json_key: str,
            expected_types: tuple[type[Any], ...],
        ) -> str | float | int | bool:
            """Retrieve a field from a dictionary and validate its type."""
            field_value = iplookup.get(json_key)
            if field_value is None:
                return 'N/A'

            if not isinstance(field_value, expected_types):
                raise TypeError(format_type_error(field_value, expected_types, f' in field "{json_key}" ({player_ip})'))
            if not isinstance(field_value, (str, float, int, bool)):
                raise TypeError(format_type_error(field_value, (str, float, int, bool), f' in field "{json_key}" ({player_ip})'))

            return field_value

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            ips_to_lookup: list[str] = []

            for player in PlayersRegistry.get_default_sorted_players():
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
                    'http://ip-api.com/batch',
                    params={'fields': FIELDS_TO_LOOKUP},
                    headers={'Content-Type': 'application/json'},
                    json=ips_to_lookup,
                    timeout=3,
                )
                response.raise_for_status()
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                gui_closed__event.wait(1)
                continue
            except requests.exceptions.HTTPError as e:
                if isinstance(e.response, requests.Response) and e.response.status_code == requests.codes.too_many_requests:  # Handle rate limiting  # pylint: disable=no-member
                    throttle_until(int(e.response.headers['X-Rl']), int(e.response.headers['X-Ttl']))
                    continue
                raise  # Re-raise other HTTP errors

            iplookup_results = response.json()
            if not isinstance(iplookup_results, list):
                raise TypeError(format_type_error(iplookup_results, list))

            for iplookup in iplookup_results:  # pyright: ignore[reportUnknownVariableType]
                if not isinstance(iplookup, dict):
                    raise TypeError(format_type_error(iplookup, dict))  # pyright: ignore[reportUnknownArgumentType]

                player_ip = iplookup.get('query')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType]
                if not isinstance(player_ip, str):
                    raise TypeError(format_type_error(player_ip, str))  # pyright: ignore[reportUnknownArgumentType]

                player = PlayersRegistry.require_player_by_ip(player_ip)
                for attr, (json_key, expected_types) in FIELD_MAPPINGS.items():
                    setattr(player.iplookup.ipapi, attr, validate_and_get_iplookup_field(player_ip, iplookup, json_key, expected_types))  # pyright: ignore[reportUnknownArgumentType]
                player.iplookup.ipapi.is_initialized = True

            throttle_until(int(response.headers['X-Rl']), int(response.headers['X-Ttl']))


def hostname_core() -> None:
    with ThreadsExceptionHandler():
        from concurrent.futures import Future, ThreadPoolExecutor

        from modules.networking.reverse_dns import lookup as reverse_dns_lookup

        with ThreadPoolExecutor(max_workers=32) as executor:
            futures: dict[Future[str], str] = {}  # Maps futures to their corresponding IPs
            pending_ips: set[str] = set()   # Tracks IPs currently being processed

            while not gui_closed__event.is_set():
                if ScriptControl.has_crashed():
                    return

                for player in PlayersRegistry.get_default_sorted_players():
                    if player.reverse_dns.is_initialized or player.ip in pending_ips:
                        continue

                    future = executor.submit(reverse_dns_lookup, player.ip)
                    futures[future] = player.ip
                    pending_ips.add(player.ip)

                if not futures:
                    gui_closed__event.wait(1)
                    continue

                for future, ip in list(futures.items()):
                    if not future.done():
                        continue

                    futures.pop(future)

                    hostname = future.result()

                    player = PlayersRegistry.require_player_by_ip(ip)
                    player.reverse_dns.hostname = hostname
                    player.reverse_dns.is_initialized = True

                gui_closed__event.wait(0.1)


def pinger_core() -> None:
    with ThreadsExceptionHandler():
        from concurrent.futures import Future, ThreadPoolExecutor

        from modules.networking.endpoint_ping_manager import (
            PingResult,
            fetch_and_parse_ping,
        )
        from modules.networking.exceptions import AllEndpointsExhaustedError

        with ThreadPoolExecutor(max_workers=32) as executor:
            futures: dict[Future[PingResult], str] = {}  # Maps futures to their corresponding IPs
            pending_ips: set[str] = set()   # Tracks IPs currently being processed

            while not gui_closed__event.is_set():
                if ScriptControl.has_crashed():
                    return

                for player in PlayersRegistry.get_default_sorted_players():
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
                        ping_result = future.result()
                    except AllEndpointsExhaustedError:
                        continue

                    player = PlayersRegistry.require_player_by_ip(ip)
                    player.ping.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
                    player.ping.ping_times = ping_result.ping_times
                    player.ping.packets_transmitted = ping_result.packets_transmitted
                    player.ping.packets_received = ping_result.packets_received
                    player.ping.packet_duplicates = ping_result.packet_duplicates
                    player.ping.packet_loss = ping_result.packet_loss
                    player.ping.packet_errors = ping_result.packet_errors
                    player.ping.rtt_min = ping_result.rtt_min
                    player.ping.rtt_avg = ping_result.rtt_avg
                    player.ping.rtt_max = ping_result.rtt_max
                    player.ping.rtt_mdev = ping_result.rtt_mdev
                    player.ping.is_initialized = True

                gui_closed__event.wait(0.1)


tshark_packets_latencies: list[tuple[datetime, timedelta]] = []
tshark_restarted_times: int = 0


def capture_core() -> None:
    with ThreadsExceptionHandler():
        def packet_callback(packet: Packet) -> None:
            from modules.networking.utils import is_private_device_ipv4

            global tshark_restarted_times

            packet_latency = datetime.now(tz=LOCAL_TZ) - packet.datetime
            tshark_packets_latencies.append((packet.datetime, packet_latency))
            if packet_latency >= timedelta(seconds=Settings.CAPTURE_OVERFLOW_TIMER):
                tshark_restarted_times += 1
                raise PacketCaptureOverflowError(Settings.CAPTURE_OVERFLOW_TIMER)

            if Settings.CAPTURE_IP_ADDRESS:
                if packet.ip.src == Settings.CAPTURE_IP_ADDRESS:
                    target_ip = packet.ip.dst
                    target_port = packet.port.dst
                elif packet.ip.dst == Settings.CAPTURE_IP_ADDRESS:
                    target_ip = packet.ip.src
                    target_port = packet.port.src
                else:
                    return  # Neither source nor destination matches the specified `Settings.CAPTURE_IP_ADDRESS`.
            else:
                is_src_private_ip = is_private_device_ipv4(packet.ip.src)
                is_dst_private_ip = is_private_device_ipv4(packet.ip.dst)

                if is_src_private_ip and is_dst_private_ip:
                    return  # Both source and destination are private IPs, no action needed.

                if is_src_private_ip:
                    target_ip = packet.ip.dst
                    target_port = packet.port.dst
                elif is_dst_private_ip:
                    target_ip = packet.ip.src
                    target_port = packet.port.src
                else:
                    return  # Neither source nor destination is a private IP address.

            player = PlayersRegistry.get_player_by_ip(target_ip)
            if player is None:
                player = PlayersRegistry.add_connected_player(
                    Player(
                        ip=target_ip,
                        port=target_port,
                        packet_datetime=packet.datetime,
                    ),
                )

                if GUIDetectionSettings.player_join_notifications_enabled:
                    show_detection_warning_popup(player, 'player_joined')

            elif player.left_event.is_set():
                player.mark_as_rejoined(
                    port=target_port,
                    packet_datetime=packet.datetime,
                )
                PlayersRegistry.move_player_to_connected(player)

                if GUIDetectionSettings.player_join_notifications_enabled:
                    show_detection_warning_popup(player, 'player_joined')
            else:
                player.mark_as_seen(
                    port=target_port,
                    packet_datetime=packet.datetime,
                )

            if player.ip in UserIPDatabases.ips_set and (
                not player.userip_detection
                or not player.userip_detection.as_processed_task
            ):
                player.userip_detection = PlayerUserIPDetection(
                    time=packet.datetime.strftime('%H:%M:%S'),
                    date_time=packet.datetime.strftime('%Y-%m-%d_%H:%M:%S'),
                )
                Thread(
                    target=process_userip_task,
                    name=f'ProcessUserIPTask-{player.ip}-connected',
                    args=(player, 'connected'),
                    daemon=True,
                ).start()

        while not gui_closed__event.is_set():
            try:
                capture.apply_on_packets(callback=packet_callback)
            except TSharkCrashExceptionError:
                if gui_closed__event.wait(3):
                    break
                raise
            except PacketCaptureOverflowError:
                continue


@dataclass(frozen=True, config={'arbitrary_types_allowed': True}, kw_only=True, slots=True)
class CellColor:
    foreground: QColor
    background: QColor


class ThreadSafeMeta(type):
    """Metaclass that ensures thread-safe access to class attributes."""

    # Define a lock for the metaclass itself to be shared across all instances of classes using this metaclass.
    _rlock: ClassVar = RLock()

    def __getattr__(cls, name: str) -> object:
        """Get an attribute from the class in a thread-safe manner."""
        with cls._rlock:
            try:
                return super().__getattribute__(name)
            except AttributeError:
                raise AttributeError(format_attribute_error(cls, name)) from None

    def __setattr__(cls, name: str, value: object) -> None:
        """Set an attribute on the class in a thread-safe manner."""
        with cls._rlock:
            super().__setattr__(name, value)


class AbstractGUIRenderingData:
    FIELDS_TO_HIDE: set[str]
    GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES: list[str]
    GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES: list[str]

    header_text: str
    SESSION_CONNECTED_TABLE__NUM_COLS: int
    session_connected_table__num_rows: int
    session_connected_table__processed_data: list[list[str]]
    session_connected_table__compiled_colors: list[list[CellColor]]
    SESSION_DISCONNECTED_TABLE__NUM_COLS: int
    session_disconnected_table__num_rows: int
    session_disconnected_table__processed_data: list[list[str]]
    session_disconnected_table__compiled_colors: list[list[CellColor]]

    session_connected_sorted_column_name: str
    session_connected_sort_order: Qt.SortOrder
    session_disconnected_sorted_column_name: str
    session_disconnected_sort_order: Qt.SortOrder


class GUIrenderingData(AbstractGUIRenderingData, metaclass=ThreadSafeMeta):
    gui_rendering_ready_event: ClassVar = Event()


def rendering_core() -> None:
    with ThreadsExceptionHandler():
        def compile_tables_header_field_names() -> tuple[list[Any], list[Any], list[Any], list[Any]]:
            gui_connected_players_table__field_names = [
                field_name
                for field_name in Settings.GUI_ALL_CONNECTED_FIELDS
                if field_name not in GUIrenderingData.FIELDS_TO_HIDE
            ]
            gui_disconnected_players_table__field_names = [
                field_name
                for field_name in Settings.GUI_ALL_DISCONNECTED_FIELDS
                if field_name not in GUIrenderingData.FIELDS_TO_HIDE
            ]
            logging_connected_players_table__field_names = list(Settings.GUI_ALL_CONNECTED_FIELDS)
            logging_disconnected_players_table__field_names = list(Settings.GUI_ALL_DISCONNECTED_FIELDS)

            return (
                gui_connected_players_table__field_names,
                gui_disconnected_players_table__field_names,
                logging_connected_players_table__field_names,
                logging_disconnected_players_table__field_names,
            )

        def parse_userip_ini_file(ini_path: Path, unresolved_ip_invalid: set[str]) -> tuple[UserIPSettings | None, dict[str, list[str]] | None]:
            def process_ini_line_output(line: str) -> str:
                return line.strip()

            from modules.constants.standalone import USERIP_INI_SETTINGS
            from modules.constants.standard import (
                RE_SETTINGS_INI_PARSER_PATTERN,
                RE_USERIP_INI_PARSER_PATTERN,
            )
            from modules.utils import (
                check_case_insensitive_and_exact_match,
                custom_str_to_bool,
                custom_str_to_nonetype,
            )
            from modules.utils_exceptions import (
                InvalidBooleanValueError,
                InvalidNoneTypeValueError,
                NoMatchFoundError,
            )

            validate_file(ini_path)

            settings: dict[str, Any] = {}
            userip: dict[str, list[str]] = {}
            current_section = None
            matched_settings: list[str] = []
            ini_data = ini_path.read_text('utf-8')
            corrected_ini_data_lines: list[str] = []

            for line in map(process_ini_line_output, ini_data.splitlines(keepends=True)):
                corrected_ini_data_lines.append(line)

                if line.startswith('[') and line.endswith(']'):
                    # we basically adding a newline if the previous line is not a newline for eyes visiblitly or idk how we say that
                    if (
                        corrected_ini_data_lines
                        and len(corrected_ini_data_lines) > 1
                        and corrected_ini_data_lines[-2]
                    ):
                        corrected_ini_data_lines.insert(-1, '')  # Insert an empty string before the last line
                    current_section = line[1:-1]
                    continue

                if current_section is None:
                    continue

                if current_section == 'Settings':
                    match = RE_SETTINGS_INI_PARSER_PATTERN.search(line)
                    if not match:
                        # If it's a newline or a comment we don't really care about rewritting at this point.
                        if not line.startswith((';', '#')) or not line:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    setting = match.group('key')
                    if setting is None:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    if not isinstance(setting, str):
                        raise TypeError(format_type_error(setting, str))
                    value = match.group('value')
                    if value is None:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    if not isinstance(value, str):
                        raise TypeError(format_type_error(value, str))

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

                    if setting not in USERIP_INI_SETTINGS:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    if setting in settings:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    matched_settings.append(setting)
                    need_rewrite_current_setting = False
                    is_setting_corrupted = False

                    if setting == 'ENABLED':
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                        except InvalidBooleanValueError:
                            is_setting_corrupted = True
                    elif setting == 'COLOR':
                        if (q_color := QColor(value)).isValid():
                            settings[setting] = q_color
                        else:
                            is_setting_corrupted = True
                    elif setting in {'LOG', 'NOTIFICATIONS'}:
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                        except InvalidBooleanValueError:
                            is_setting_corrupted = True
                    elif setting == 'VOICE_NOTIFICATIONS':
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_bool(value, only_match_against=False)
                        except InvalidBooleanValueError:
                            try:
                                case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ('Male', 'Female'))
                                settings[setting] = normalized_match
                                if not case_sensitive_match:
                                    need_rewrite_current_setting = True
                            except NoMatchFoundError:
                                is_setting_corrupted = True
                    elif setting == 'PROTECTION':
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_bool(value, only_match_against=False)
                        except InvalidBooleanValueError:
                            try:
                                case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ('Suspend_Process', 'Exit_Process', 'Restart_Process', 'Shutdown_PC', 'Restart_PC'))
                                settings[setting] = normalized_match
                                if not case_sensitive_match:
                                    need_rewrite_current_setting = True
                            except NoMatchFoundError:
                                is_setting_corrupted = True
                    elif setting in {'PROTECTION_PROCESS_PATH', 'PROTECTION_RESTART_PROCESS_PATH'}:
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_nonetype(value)
                        except InvalidNoneTypeValueError:
                            stripped_value = value.strip("\"'")
                            if value != stripped_value:
                                is_setting_corrupted = True
                            settings[setting] = Path(stripped_value)
                    elif setting == 'PROTECTION_SUSPEND_PROCESS_MODE':
                        try:
                            case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ('Auto', 'Manual'))
                            settings[setting] = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        except NoMatchFoundError:
                            try:
                                if '.' in value:
                                    protection_suspend_process_mode = float(value)
                                else:
                                    protection_suspend_process_mode = int(value)
                            except (ValueError, TypeError):
                                is_setting_corrupted = True
                            else:
                                if protection_suspend_process_mode >= 0:
                                    settings[setting] = protection_suspend_process_mode
                                else:
                                    is_setting_corrupted = True

                    if is_setting_corrupted:
                        if ini_path not in UserIPDatabases.notified_settings_corrupted:
                            UserIPDatabases.notified_settings_corrupted.add(ini_path)
                            Thread(
                                target=MsgBox.show,
                                name=f'UserIPConfigFileError-{ini_path.name}',
                                kwargs={
                                    'title': TITLE,
                                    'text': format_triple_quoted_text(f"""
                                        ERROR:
                                            Corrupted UserIP Database File (Settings)

                                        INFOS:
                                            UserIP database file:
                                            "{ini_path}"
                                            has an invalid settings value:

                                            {setting}={value}

                                        For more information on formatting, please refer to the
                                        documentation:
                                        https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration
                                    """),
                                    'style': MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND,
                                },
                                daemon=True,
                            ).start()
                        return None, None

                    if need_rewrite_current_setting:
                        corrected_ini_data_lines[-1] = f'{setting}={settings[setting]}'

                elif current_section == 'UserIP':
                    match = RE_USERIP_INI_PARSER_PATTERN.search(line)
                    if not match:
                        continue
                    username = match.group('username')
                    if username is None:
                        continue
                    if not isinstance(username, str):
                        raise TypeError(format_type_error(username, str))
                    ip = match.group('ip')
                    if ip is None:
                        continue
                    if not isinstance(ip, str):
                        raise TypeError(format_type_error(ip, str))

                    username = username.strip()
                    if not username:
                        continue
                    ip = ip.strip()
                    if not ip:
                        continue

                    if not is_ipv4_address(ip):
                        unresolved_ip_invalid.add(f'{ini_path}={username}={ip}')
                        if f'{ini_path}={username}={ip}' not in UserIPDatabases.notified_ip_invalid:
                            Thread(
                                target=MsgBox.show,
                                name=f'UserIPInvalidEntryError-{ini_path.name}_{username}={ip}',
                                kwargs={
                                    'title': TITLE,
                                    'text': format_triple_quoted_text(f"""
                                        ERROR:
                                            UserIP database invalid IP address

                                        INFOS:
                                            The IP address from this database entry is invalid.

                                        DEBUG:
                                            {ini_path}
                                            {username}={ip}

                                        For more information on formatting, please refer to the
                                        documentation:
                                        https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration
                                    """),
                                    'style': MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND,
                                },
                                daemon=True,
                            ).start()
                            UserIPDatabases.notified_ip_invalid.add(f'{ini_path}={username}={ip}')
                        continue

                    if username in userip:
                        if ip not in userip[username]:
                            userip[username].append(ip)
                    else:
                        userip[username] = [ip]

            list_of_missing_settings = [setting for setting in USERIP_INI_SETTINGS if setting not in matched_settings]
            number_of_settings_missing = len(list_of_missing_settings)

            if number_of_settings_missing > 0:
                if ini_path not in UserIPDatabases.notified_settings_corrupted:
                    UserIPDatabases.notified_settings_corrupted.add(ini_path)
                    Thread(
                        target=MsgBox.show,
                        name=f'UserIPConfigFileError-{ini_path.name}',
                        kwargs={
                            'title': TITLE,
                            'text': format_triple_quoted_text(f"""
                                ERROR:
                                    Missing setting{pluralize(number_of_settings_missing)} in UserIP Database File

                                INFOS:
                                    {number_of_settings_missing} missing setting{pluralize(number_of_settings_missing)} in UserIP database file:
                                    "{ini_path}"

                                    {"\n                ".join(f"<{setting.upper()}>" for setting in list_of_missing_settings)}

                                For more information on formatting, please refer to the
                                documentation:
                                https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration
                            """),
                            'style': MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND,
                        },
                        daemon=True,
                    ).start()
                return None, None

            if ini_path in UserIPDatabases.notified_settings_corrupted:
                UserIPDatabases.notified_settings_corrupted.remove(ini_path)

            # Basically always have a newline ending
            if (
                len(corrected_ini_data_lines) > 1
                and corrected_ini_data_lines[-1]
            ):
                corrected_ini_data_lines.append('')

            fixed_ini_data = '\n'.join(corrected_ini_data_lines)

            if ini_data != fixed_ini_data:
                ini_path.write_text(fixed_ini_data, encoding='utf-8')

            return UserIPSettings(
                settings['ENABLED'],
                settings['COLOR'],
                settings['LOG'],
                settings['NOTIFICATIONS'],
                settings['VOICE_NOTIFICATIONS'],
                settings['PROTECTION'],
                settings['PROTECTION_PROCESS_PATH'],
                settings['PROTECTION_RESTART_PROCESS_PATH'],
                settings['PROTECTION_SUSPEND_PROCESS_MODE'],
            ), userip

        def update_userip_databases() -> float:
            from modules.constants.standard import USERIP_DATABASES_PATH

            # pylint: disable=invalid-name
            DEFAULT_USERIP_FILE_HEADER = format_triple_quoted_text(f"""
                ;;-----------------------------------------------------------------------------
                ;; {TITLE} User IP default database file
                ;;-----------------------------------------------------------------------------
                ;; Lines starting with ";" or "#" symbols are commented lines.
                ;;
                ;; For detailed explanations of each setting, please refer to the following documentation:
                ;; https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration
                ;;-----------------------------------------------------------------------------
                [Settings]
            """)

            DEFAULT_USERIP_FILES_SETTINGS = {
                USERIP_DATABASES_PATH / 'Blacklist.ini': """
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
                USERIP_DATABASES_PATH / 'Enemylist.ini': """
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
                USERIP_DATABASES_PATH / 'Friendlist.ini': """
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
                USERIP_DATABASES_PATH / 'Randomlist.ini': """
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
                USERIP_DATABASES_PATH / 'Searchlist.ini': """
                    ENABLED=True
                    COLOR=BLUE
                    LOG=True
                    NOTIFICATIONS=False
                    VOICE_NOTIFICATIONS=Female
                    PROTECTION=False
                    PROTECTION_PROCESS_PATH=None
                    PROTECTION_RESTART_PROCESS_PATH=None
                    PROTECTION_SUSPEND_PROCESS_MODE=Auto
                """,
            }

            DEFAULT_USERIP_FILE_FOOTER = format_triple_quoted_text("""
                [UserIP]
                # Add users below in this format: username=IP
                # Examples:
                # username1=192.168.1.1
                # username2=127.0.0.1
                # username3=255.255.255.255
            """, add_trailing_newline=True)
            # pylint: enable=invalid-name

            USERIP_DATABASES_PATH.mkdir(parents=True, exist_ok=True)

            for userip_path, settings in DEFAULT_USERIP_FILES_SETTINGS.items():
                if not userip_path.is_file():
                    file_content = f'{DEFAULT_USERIP_FILE_HEADER}\n\n{settings}\n\n{DEFAULT_USERIP_FILE_FOOTER}'
                    userip_path.write_text(file_content, encoding='utf-8')

            # Remove deleted files from notified settings conflicts
            # TODO(BUZZARDGTA): I should also warn again on another error, but it'd probably require a DICT then.
            for file_path in set(UserIPDatabases.notified_settings_corrupted):
                if not file_path.is_file():
                    UserIPDatabases.notified_settings_corrupted.remove(file_path)

            new_databases: list[tuple[Path, UserIPSettings, dict[str, list[str]]]] = []
            unresolved_ip_invalid: set[str] = set()

            for userip_path in USERIP_DATABASES_PATH.rglob('*.ini'):
                parsed_settings, parsed_data = parse_userip_ini_file(userip_path, unresolved_ip_invalid)
                if parsed_settings is None or parsed_data is None:
                    continue
                new_databases.append((userip_path, parsed_settings, parsed_data))

            UserIPDatabases.populate(new_databases)

            resolved_ip_invalids = UserIPDatabases.notified_ip_invalid - unresolved_ip_invalid
            for resolved_database_entry in resolved_ip_invalids:
                UserIPDatabases.notified_ip_invalid.remove(resolved_database_entry)

            UserIPDatabases.build()

            return time.monotonic()

        def get_country_info(ip_address: str) -> tuple[str, str]:
            country_name = 'N/A'
            country_code = 'N/A'

            if geoip2_enabled and geolite2_country_reader is not None:
                try:
                    response = geolite2_country_reader.country(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    country_name = str(response.country.name)
                    country_code = str(response.country.iso_code)

            return country_name, country_code

        def get_city_info(ip_address: str) -> str:
            city = 'N/A'

            if geoip2_enabled and geolite2_city_reader is not None:
                try:
                    response = geolite2_city_reader.city(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    city = str(response.city.name)

            return city

        def get_asn_info(ip_address: str) -> str:
            asn = 'N/A'

            if geoip2_enabled and geolite2_asn_reader is not None:
                try:
                    response = geolite2_asn_reader.asn(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    asn = str(response.autonomous_system_organization)

            return asn

        def process_session_logging() -> None:
            def format_player_logging_datetime(datetime_object: datetime) -> str:
                return datetime_object.strftime('%m/%d/%Y %H:%M:%S.%f')[:-3]

            def format_player_logging_usernames(player: Player) -> str:
                return ', '.join(player.usernames) if player.usernames else ''

            def format_player_logging_ip(player_ip: str) -> str:
                if SessionHost.player and SessionHost.player.ip == player_ip:
                    return f'{player_ip} 👑'
                return player_ip

            def format_player_logging_middle_ports(player: Player) -> str:
                if player.ports.middle:
                    return ', '.join(map(str, reversed(player.ports.middle)))
                return ''

            def add_sort_arrow_char_to_sorted_logging_table_field(field_names: Sequence[str], sorted_field: str, sort_order: Qt.SortOrder) -> list[str]:
                arrow = ' \u2193' if sort_order == Qt.SortOrder.DescendingOrder else ' \u2191'  # Down arrow for descending, up arrow for ascending
                return [
                    field + arrow if field == sorted_field else field
                    for field in field_names
                ]

            def calculate_table_padding(connected_players: list[Player], disconnected_players: list[Player]) -> tuple[int, int, int, int]:
                """Calculate optimal padding for table columns based on player data."""
                connected_country_padding = 0
                connected_continent_padding = 0
                disconnected_country_padding = 0
                disconnected_continent_padding = 0

                # Calculate optimal padding for connected players
                for player in connected_players:
                    country_len = len(player.iplookup.geolite2.country)
                    continent_len = len(player.iplookup.ipapi.continent)

                    # Only include in padding calculation if within threshold
                    if country_len <= TABLE_COUNTRY_COLUMN_LENGTH_THRESHOLD:
                        connected_country_padding = max(connected_country_padding, country_len)
                    if continent_len <= TABLE_CONTINENT_COLUMN_LENGTH_THRESHOLD:
                        connected_continent_padding = max(connected_continent_padding, continent_len)

                # Calculate optimal padding for disconnected players
                for player in disconnected_players:
                    country_len = len(player.iplookup.geolite2.country)
                    continent_len = len(player.iplookup.ipapi.continent)

                    # Only include in padding calculation if within threshold
                    if country_len <= TABLE_COUNTRY_COLUMN_LENGTH_THRESHOLD:
                        disconnected_country_padding = max(disconnected_country_padding, country_len)
                    if continent_len <= TABLE_CONTINENT_COLUMN_LENGTH_THRESHOLD:
                        disconnected_continent_padding = max(disconnected_continent_padding, continent_len)

                return connected_country_padding, connected_continent_padding, disconnected_country_padding, disconnected_continent_padding

            TABLE_COUNTRY_COLUMN_LENGTH_THRESHOLD = 27  # pylint: disable=invalid-name
            TABLE_CONTINENT_COLUMN_LENGTH_THRESHOLD = 13  # pylint: disable=invalid-name

            logging_connected_players__field_names__with_down_arrow = add_sort_arrow_char_to_sorted_logging_table_field(LOGGING_CONNECTED_PLAYERS_TABLE__FIELD_NAMES, 'Last Rejoin', Qt.SortOrder.DescendingOrder)
            logging_disconnected_players__field_names__with_down_arrow = add_sort_arrow_char_to_sorted_logging_table_field(LOGGING_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES, 'Last Seen', Qt.SortOrder.AscendingOrder)
            row_texts: list[str] = []

            # Calculate optimal padding for both connected and disconnected players
            (session_connected__padding_country_name,
             session_connected__padding_continent_name,
             session_disconnected__padding_country_name,
             session_disconnected__padding_continent_name) = calculate_table_padding(session_connected, session_disconnected)

            logging_connected_players_table = PrettyTable()
            logging_connected_players_table.set_style(TableStyle.SINGLE_BORDER)
            logging_connected_players_table.title = f'Player{pluralize(len(session_connected))} connected in your session ({len(session_connected)}):'
            logging_connected_players_table.field_names = logging_connected_players__field_names__with_down_arrow
            logging_connected_players_table.align = 'l'
            for player in session_connected:
                row_texts = []
                row_texts.append(f'{format_player_logging_usernames(player)}')
                row_texts.append(f'{format_player_logging_datetime(player.datetime.first_seen)}')
                row_texts.append(f'{format_player_logging_datetime(player.datetime.last_rejoin)}')
                row_texts.append(f'{player.rejoins}')
                row_texts.append(f'{player.total_packets}')
                row_texts.append(f'{player.packets}')
                row_texts.append(f'{player.pps.rate}')
                row_texts.append(f'{player.ppm.rate}')
                row_texts.append(f'{format_player_logging_ip(player.ip)}')
                row_texts.append(f'{player.reverse_dns.hostname}')
                row_texts.append(f'{player.ports.last}')
                row_texts.append(f'{format_player_logging_middle_ports(player)}')
                row_texts.append(f'{player.ports.first}')
                row_texts.append(f'{player.iplookup.ipapi.continent:<{session_connected__padding_continent_name}} ({player.iplookup.ipapi.continent_code})')
                row_texts.append(f'{player.iplookup.geolite2.country:<{session_connected__padding_country_name}} ({player.iplookup.geolite2.country_code})')
                row_texts.append(f'{player.iplookup.ipapi.region}')
                row_texts.append(f'{player.iplookup.ipapi.region_code}')
                row_texts.append(f'{player.iplookup.geolite2.city}')
                row_texts.append(f'{player.iplookup.ipapi.district}')
                row_texts.append(f'{player.iplookup.ipapi.zip_code}')
                row_texts.append(f'{player.iplookup.ipapi.lat}')
                row_texts.append(f'{player.iplookup.ipapi.lon}')
                row_texts.append(f'{player.iplookup.ipapi.time_zone}')
                row_texts.append(f'{player.iplookup.ipapi.offset}')
                row_texts.append(f'{player.iplookup.ipapi.currency}')
                row_texts.append(f'{player.iplookup.ipapi.org}')
                row_texts.append(f'{player.iplookup.ipapi.isp}')
                row_texts.append(f'{player.iplookup.geolite2.asn}')
                row_texts.append(f'{player.iplookup.ipapi.asn}')
                row_texts.append(f'{player.iplookup.ipapi.as_name}')
                row_texts.append(f'{player.iplookup.ipapi.mobile}')
                row_texts.append(f'{player.iplookup.ipapi.proxy}')
                row_texts.append(f'{player.iplookup.ipapi.hosting}')
                row_texts.append(f'{player.ping.is_pinging}')
                logging_connected_players_table.add_row(row_texts)

            logging_disconnected_players_table = PrettyTable()
            logging_disconnected_players_table.set_style(TableStyle.SINGLE_BORDER)
            logging_disconnected_players_table.title = f"Player{pluralize(len(session_disconnected))} who've left your session ({len(session_disconnected)}):"
            logging_disconnected_players_table.field_names = logging_disconnected_players__field_names__with_down_arrow
            logging_disconnected_players_table.align = 'l'
            for player in session_disconnected:
                row_texts = []
                row_texts.append(f'{format_player_logging_usernames(player)}')
                row_texts.append(f'{format_player_logging_datetime(player.datetime.first_seen)}')
                row_texts.append(f'{format_player_logging_datetime(player.datetime.last_rejoin)}')
                row_texts.append(f'{format_player_logging_datetime(player.datetime.last_seen)}')
                row_texts.append(f'{player.rejoins}')
                row_texts.append(f'{player.total_packets}')
                row_texts.append(f'{player.packets}')
                row_texts.append(f'{player.ip}')
                row_texts.append(f'{player.reverse_dns.hostname}')
                row_texts.append(f'{player.ports.last}')
                row_texts.append(f'{format_player_logging_middle_ports(player)}')
                row_texts.append(f'{player.ports.first}')
                row_texts.append(f'{player.iplookup.ipapi.continent:<{session_disconnected__padding_continent_name}} ({player.iplookup.ipapi.continent_code})')
                row_texts.append(f'{player.iplookup.geolite2.country:<{session_disconnected__padding_country_name}} ({player.iplookup.geolite2.country_code})')
                row_texts.append(f'{player.iplookup.ipapi.region}')
                row_texts.append(f'{player.iplookup.ipapi.region_code}')
                row_texts.append(f'{player.iplookup.geolite2.city}')
                row_texts.append(f'{player.iplookup.ipapi.district}')
                row_texts.append(f'{player.iplookup.ipapi.zip_code}')
                row_texts.append(f'{player.iplookup.ipapi.lat}')
                row_texts.append(f'{player.iplookup.ipapi.lon}')
                row_texts.append(f'{player.iplookup.ipapi.time_zone}')
                row_texts.append(f'{player.iplookup.ipapi.offset}')
                row_texts.append(f'{player.iplookup.ipapi.currency}')
                row_texts.append(f'{player.iplookup.ipapi.org}')
                row_texts.append(f'{player.iplookup.ipapi.isp}')
                row_texts.append(f'{player.iplookup.geolite2.asn}')
                row_texts.append(f'{player.iplookup.ipapi.asn}')
                row_texts.append(f'{player.iplookup.ipapi.as_name}')
                row_texts.append(f'{player.iplookup.ipapi.mobile}')
                row_texts.append(f'{player.iplookup.ipapi.proxy}')
                row_texts.append(f'{player.iplookup.ipapi.hosting}')
                row_texts.append(f'{player.ping.is_pinging}')
                logging_disconnected_players_table.add_row(row_texts)

            from modules.constants.standard import SESSIONS_LOGGING_PATH

            # Check if the directories exist, if not create them
            if not SESSIONS_LOGGING_PATH.parent.is_dir():
                SESSIONS_LOGGING_PATH.parent.mkdir(parents=True)  # Create the directories if they don't exist

            # Check if the file exists, if not create it
            if not SESSIONS_LOGGING_PATH.is_file():
                SESSIONS_LOGGING_PATH.touch()  # Create the file if it doesn't exist

            SESSIONS_LOGGING_PATH.write_text(logging_connected_players_table.get_string() + '\n' + logging_disconnected_players_table.get_string(), encoding='utf-8')  # pyright: ignore[reportUnknownMemberType]

        def process_gui_session_tables_rendering() -> tuple[int, list[list[str]], list[list[CellColor]], int, list[list[str]], list[list[CellColor]]]:
            def format_player_gui_datetime(datetime_object: datetime) -> str:
                formatted_elapsed = None

                if Settings.GUI_DATE_FIELDS_SHOW_ELAPSED:
                    elapsed_time = datetime.now(tz=LOCAL_TZ) - datetime_object

                    hours, remainder = divmod(elapsed_time.total_seconds(), 3600)
                    minutes, remainder = divmod(remainder, 60)
                    seconds, milliseconds = divmod(remainder * 1000, 1000)

                    elapsed_parts: list[str] = []
                    if hours >= 1:
                        elapsed_parts.append(f'{int(hours):02}h')
                    if elapsed_parts or minutes >= 1:
                        elapsed_parts.append(f'{int(minutes):02}m')
                    if elapsed_parts or seconds >= 1:
                        elapsed_parts.append(f'{int(seconds):02}s')
                    if not elapsed_parts and milliseconds > 0:
                        elapsed_parts.append(f'{int(milliseconds):03}ms')

                    formatted_elapsed = ' '.join(elapsed_parts)

                    if Settings.GUI_DATE_FIELDS_SHOW_DATE is False and Settings.GUI_DATE_FIELDS_SHOW_TIME is False:
                        return formatted_elapsed

                parts: list[str] = []
                if Settings.GUI_DATE_FIELDS_SHOW_DATE:
                    parts.append(datetime_object.strftime('%m/%d/%Y'))
                if Settings.GUI_DATE_FIELDS_SHOW_TIME:
                    parts.append(datetime_object.strftime('%H:%M:%S.%f')[:-3])
                if not parts:
                    raise InvalidDateFieldConfigurationError

                formatted_datetime = ' '.join(parts)

                if formatted_elapsed:
                    formatted_datetime += f' ({formatted_elapsed})'

                return formatted_datetime

            def format_player_gui_usernames(player: Player) -> str:
                return ', '.join(player.usernames) if player.usernames else ''

            def format_player_gui_ip(player_ip: str) -> str:
                if SessionHost.player and SessionHost.player.ip == player_ip:
                    return f'{player_ip} 👑'
                return player_ip

            def format_player_gui_middle_ports(player: Player) -> str:
                if player.ports.middle:
                    return ', '.join(map(str, reversed(player.ports.middle)))
                return ''

            def get_player_rate_color(color: QColor, rate: int, *, is_first_calculation: bool) -> QColor:
                """Determine the color for player rates based on given thresholds."""
                from modules.constants.standalone import RATE_LOW, RATE_MAX, RATE_ZERO

                if not is_first_calculation:
                    if rate == RATE_ZERO:
                        return QColor('red')
                    if RATE_LOW <= rate <= RATE_MAX:
                        return QColor('yellow')
                return color

            from modules.constants.external import (
                HARDCODED_DEFAULT_TABLE_BACKGROUND_CELL_COLOR,
            )

            row_texts: list[str] = []
            session_connected_table__processed_data: list[list[str]] = []
            session_connected_table__compiled_colors: list[list[CellColor]] = []
            session_disconnected_table__processed_data: list[list[str]] = []
            session_disconnected_table__compiled_colors: list[list[CellColor]] = []

            for player in session_connected:
                if player.userip and player.userip.usernames:
                    row_fg_color = QColor('white')
                    row_bg_color = player.userip.settings.COLOR
                else:
                    row_fg_color = QColor('lime')
                    row_bg_color = HARDCODED_DEFAULT_TABLE_BACKGROUND_CELL_COLOR

                # Initialize a list for cell colors for the current row, creating a new CellColor object for each column
                row_colors = [
                    CellColor(foreground=row_fg_color, background=row_bg_color)
                    for _ in range(GUIrenderingData.SESSION_CONNECTED_TABLE__NUM_COLS)
                ]

                row_texts = []
                row_texts.append(f'{format_player_gui_usernames(player)}')
                row_texts.append(f'{format_player_gui_datetime(player.datetime.first_seen)}')
                row_texts.append(f'{format_player_gui_datetime(player.datetime.last_rejoin)}')
                row_texts.append(f'{player.rejoins}')
                row_texts.append(f'{player.total_packets}')
                row_texts.append(f'{player.packets}')
                if 'PPS' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_colors[CONNECTED_COLUMN_MAPPING['PPS']] = dataclasses.replace(row_colors[CONNECTED_COLUMN_MAPPING['PPS']], foreground=get_player_rate_color(row_fg_color, player.pps.rate, is_first_calculation=player.pps.is_first_calculation))
                    row_texts.append(f'{player.pps.rate}')
                if 'PPM' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_colors[CONNECTED_COLUMN_MAPPING['PPM']] = dataclasses.replace(row_colors[CONNECTED_COLUMN_MAPPING['PPM']], foreground=get_player_rate_color(row_fg_color, player.ppm.rate, is_first_calculation=player.ppm.is_first_calculation))
                    row_texts.append(f'{player.ppm.rate}')
                row_texts.append(f'{format_player_gui_ip(player.ip)}')
                if 'Hostname' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.reverse_dns.hostname}')
                if 'Last Port' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.ports.last}')
                if 'Middle Ports' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{format_player_gui_middle_ports(player)}')
                if 'First Port' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.ports.first}')
                if 'Continent' not in GUIrenderingData.FIELDS_TO_HIDE:
                    if Settings.GUI_FIELD_SHOW_CONTINENT_CODE:
                        row_texts.append(f'{player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})')
                    else:
                        row_texts.append(f'{player.iplookup.ipapi.continent}')
                if 'Country' not in GUIrenderingData.FIELDS_TO_HIDE:
                    if Settings.GUI_FIELD_SHOW_COUNTRY_CODE:
                        row_texts.append(f'{player.iplookup.geolite2.country} ({player.iplookup.geolite2.country_code})')
                    else:
                        row_texts.append(f'{player.iplookup.geolite2.country}')
                if 'Region' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.region}')
                if 'R. Code' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.region_code}')
                if 'City' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.geolite2.city}')
                if 'District' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.district}')
                if 'ZIP Code' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.zip_code}')
                if 'Lat' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.lat}')
                if 'Lon' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.lon}')
                if 'Time Zone' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.time_zone}')
                if 'Offset' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.offset}')
                if 'Currency' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.currency}')
                if 'Organization' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.org}')
                if 'ISP' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.isp}')
                if 'ASN / ISP' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.geolite2.asn}')
                if 'AS' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.asn}')
                if 'ASN' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.as_name}')
                if 'Mobile' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.mobile}')
                if 'VPN' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.proxy}')
                if 'Hosting' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.hosting}')
                if 'Pinging' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.ping.is_pinging}')

                session_connected_table__processed_data.append(row_texts)
                session_connected_table__compiled_colors.append(row_colors)

            for player in session_disconnected:
                if player.userip and player.userip.usernames:
                    row_fg_color = QColor('white')
                    row_bg_color = player.userip.settings.COLOR
                else:
                    row_fg_color = QColor('red')
                    row_bg_color = HARDCODED_DEFAULT_TABLE_BACKGROUND_CELL_COLOR

                # Initialize a list for cell colors for the current row, creating a new CellColor object for each column
                row_colors = [CellColor(foreground=row_fg_color, background=row_bg_color) for _ in range(GUIrenderingData.SESSION_DISCONNECTED_TABLE__NUM_COLS)]

                row_texts = []
                row_texts.append(f'{format_player_gui_usernames(player)}')
                row_texts.append(f'{format_player_gui_datetime(player.datetime.first_seen)}')
                row_texts.append(f'{format_player_gui_datetime(player.datetime.last_rejoin)}')
                row_texts.append(f'{format_player_gui_datetime(player.datetime.last_seen)}')
                row_texts.append(f'{player.rejoins}')
                row_texts.append(f'{player.total_packets}')
                row_texts.append(f'{player.packets}')
                row_texts.append(f'{player.ip}')
                if 'Hostname' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.reverse_dns.hostname}')
                if 'Last Port' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.ports.last}')
                if 'Middle Ports' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{format_player_gui_middle_ports(player)}')
                if 'First Port' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.ports.first}')
                if 'Continent' not in GUIrenderingData.FIELDS_TO_HIDE:
                    if Settings.GUI_FIELD_SHOW_CONTINENT_CODE:
                        row_texts.append(f'{player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})')
                    else:
                        row_texts.append(f'{player.iplookup.ipapi.continent}')
                if 'Country' not in GUIrenderingData.FIELDS_TO_HIDE:
                    if Settings.GUI_FIELD_SHOW_COUNTRY_CODE:
                        row_texts.append(f'{player.iplookup.geolite2.country} ({player.iplookup.geolite2.country_code})')
                    else:
                        row_texts.append(f'{player.iplookup.geolite2.country}')
                if 'Region' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.region}')
                if 'R. Code' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.region_code}')
                if 'City' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.geolite2.city}')
                if 'District' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.district}')
                if 'ZIP Code' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.zip_code}')
                if 'Lat' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.lat}')
                if 'Lon' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.lon}')
                if 'Time Zone' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.time_zone}')
                if 'Offset' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.offset}')
                if 'Currency' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.currency}')
                if 'Organization' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.org}')
                if 'ISP' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.isp}')
                if 'ASN / ISP' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.geolite2.asn}')
                if 'AS' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.asn}')
                if 'ASN' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.as_name}')
                if 'Mobile' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.mobile}')
                if 'VPN' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.proxy}')
                if 'Hosting' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.iplookup.ipapi.hosting}')
                if 'Pinging' not in GUIrenderingData.FIELDS_TO_HIDE:
                    row_texts.append(f'{player.ping.is_pinging}')

                session_disconnected_table__processed_data.append(row_texts)
                session_disconnected_table__compiled_colors.append(row_colors)

            return (
                len(session_connected_table__processed_data),
                session_connected_table__processed_data,
                session_connected_table__compiled_colors,
                len(session_disconnected_table__processed_data),
                session_disconnected_table__processed_data,
                session_disconnected_table__compiled_colors,
            )

        def generate_gui_header_text(global_pps_rate: int) -> str:
            from modules.constants.standalone import (
                PPS_THRESHOLD_CRITICAL,
                PPS_THRESHOLD_WARNING,
            )

            one_second_ago = datetime.now(tz=LOCAL_TZ) - timedelta(seconds=1)

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

            # For reference, in a GTA Online session, the packets per second (PPS) typically range from 0 (solo session) to 1500 (public session, 32 players).
            # If the packet rate exceeds these ranges, we flag them with yellow or red color to indicate potential issues (such as scanning unwanted packets outside of the GTA game).
            # Also these values averagely indicates the max performances my script can run at during my testings. Luckely it's just enough to process GTA V game.
            if global_pps_rate >= PPS_THRESHOLD_CRITICAL:
                pps_color = '<span style="color: red;">'
            elif global_pps_rate >= PPS_THRESHOLD_WARNING:
                pps_color = '<span style="color: yellow;">'
            else:
                pps_color = '<span style="color: green;">'

            is_vpn_mode_enabled = 'Enabled' if vpn_mode_enabled else 'Disabled'
            is_arp_enabled = 'Enabled' if selected_interface.is_arp else 'Disabled'
            displayed_capture_ip_address = Settings.CAPTURE_IP_ADDRESS if Settings.CAPTURE_IP_ADDRESS else 'N/A'
            color_tshark_restarted_time = '<span style="color: green;">' if not tshark_restarted_times else '<span style="color: red;">'
            if Settings.DISCORD_PRESENCE and discord_rpc_manager is not None:
                rpc_message = ' RPC:<span style="color: green;">Connected</span>' if discord_rpc_manager.connection_status.is_set() else ' RPC:<span style="color: yellow;">Waiting for Discord</span>'
            else:
                rpc_message = ''

            invalid_ip_count = len(UserIPDatabases.notified_ip_invalid)
            conflict_ip_count = len(UserIPDatabases.notified_ip_conflicts)
            corrupted_settings_count = len(UserIPDatabases.notified_settings_corrupted)

            header = f"""
            <div style="background: linear-gradient(90deg, #2e3440, #4c566a); color: white; padding: 20px; border: 2px solid #88c0d0; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.3);">
                <div>
                    <span style="font-size: 24px; color: #88c0d0">{TITLE}</span>&nbsp;&nbsp;<span style="font-size: 14px; color: #aaa">{VERSION}</span>
                </div>
                <p style="font-size: 16px; margin: 5px 0;">
                    The best FREE and Open-Source packet sniffer, aka IP puller.
                </p>
                <p style="font-size: 14px; margin: 5px 0;">
                    Scanning on interface <span style="color: yellow;">{capture.interface}</span> | IP:<span style="color: yellow;">{displayed_capture_ip_address}</span> | ARP:<span style="color: yellow;">{is_arp_enabled}</span> | VPN:<span style="color: yellow;">{is_vpn_mode_enabled}</span> | Preset:<span style="color: yellow;">{Settings.CAPTURE_PROGRAM_PRESET}</span>
                </p>
                <p style="font-size: 14px; margin: 5px 0;">
                    Packets latency per sec:{latency_color}{avg_latency_rounded}</span>/<span style="color: green;">{Settings.CAPTURE_OVERFLOW_TIMER}</span> (tshark restart{pluralize(tshark_restarted_times)}:{color_tshark_restarted_time}{tshark_restarted_times}</span>) PPS:{pps_color}{global_pps_rate}</span>{rpc_message}
                </p>
            </div>
            """

            if any([invalid_ip_count, conflict_ip_count, corrupted_settings_count]):
                num_of_userip_files = len(UserIPDatabases.get_userip_database_filepaths())

                header += '───────────────────────────────────────────────────────────────────────────────────────────────────<br>'
                if invalid_ip_count:
                    header += f'Number of invalid IP{pluralize(invalid_ip_count)} in UserIP file{pluralize(num_of_userip_files)}: <span style="color: red;">{invalid_ip_count}</span><br>'
                if conflict_ip_count:
                    header += f'Number of conflicting IP{pluralize(conflict_ip_count)} in UserIP file{pluralize(num_of_userip_files)}: <span style="color: red;">{conflict_ip_count}</span><br>'
                if corrupted_settings_count:
                    header += f'Number of corrupted setting(s) in UserIP file{pluralize(num_of_userip_files)}: <span style="color: red;">{corrupted_settings_count}</span><br>'
                header += '───────────────────────────────────────────────────────────────────────────────────────────────────'
            return header

        GUIrenderingData.FIELDS_TO_HIDE = set(Settings.GUI_FIELDS_TO_HIDE)
        (
            GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES,
            GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES,
            LOGGING_CONNECTED_PLAYERS_TABLE__FIELD_NAMES,  # pylint: disable=invalid-name
            LOGGING_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES,  # pylint: disable=invalid-name
        ) = compile_tables_header_field_names()

        GUIrenderingData.SESSION_CONNECTED_TABLE__NUM_COLS = len(GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES)
        GUIrenderingData.SESSION_DISCONNECTED_TABLE__NUM_COLS = len(GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES)
        # Define the column name to index mapping for connected and disconnected players
        CONNECTED_COLUMN_MAPPING = {header: index for index, header in enumerate(GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES)}  # pylint: disable=invalid-name
        # DISCONNECTED_COLUMN_MAPPING = {header: index for index, header in enumerate(GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES)}

        from modules.constants.local import COUNTRY_FLAGS_FOLDER_PATH
        from modules.rendering_core.modmenu_logs_parser import ModMenuLogsParser

        last_userip_parse_time = None
        last_session_logging_processing_time = None

        discord_rpc_manager = None
        if Settings.DISCORD_PRESENCE:
            from modules.constants.standalone import DISCORD_APPLICATION_ID
            from modules.discord.rpc import DiscordRPC

            discord_rpc_manager = DiscordRPC(client_id=DISCORD_APPLICATION_ID)

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            if last_userip_parse_time is None or time.monotonic() - last_userip_parse_time >= 1.0:
                last_userip_parse_time = update_userip_databases()

            ModMenuLogsParser.refresh()

            global_pps_rate = 0

            session_connected, session_disconnected = PlayersRegistry.get_default_sorted_connected_and_disconnected_players()
            for player in session_connected.copy():
                if (
                    not player.left_event.is_set()
                    and (datetime.now(tz=LOCAL_TZ) - player.datetime.last_seen).total_seconds() >= Settings.GUI_DISCONNECTED_PLAYERS_TIMER
                ):
                    player.mark_as_left()
                    session_connected.remove(player)
                    session_disconnected.append(player)

                    if GUIDetectionSettings.player_leave_notifications_enabled:
                        show_detection_warning_popup(player, 'player_left')

                    continue

                # Calculate PPS every second
                if (time.monotonic() - player.pps.last_update_time) >= 1.0:
                    player.pps.update_rate(player.pps.counter)

                # Calculate PPM every minute
                if (time.monotonic() - player.ppm.last_update_time) >= 60.0:  # noqa: PLR2004
                    player.ppm.update_rate(player.ppm.counter)

                global_pps_rate += player.pps.rate

            for player in session_connected + session_disconnected:
                if player.userip and player.ip not in UserIPDatabases.ips_set:
                    player.userip = None
                    player.userip_detection = None

                modmenu_usernames_for_player = ModMenuLogsParser.get_usernames_by_ip(player.ip)
                if modmenu_usernames_for_player:
                    if player.mod_menus is None:
                        player.mod_menus = PlayerModMenus(
                            usernames=modmenu_usernames_for_player,
                        )
                    else:
                        player.mod_menus.usernames[:] = modmenu_usernames_for_player
                else:
                    player.mod_menus = None

                player.usernames = dedup_preserve_order(
                    player.userip.usernames if player.userip else [],
                    player.mod_menus.usernames if player.mod_menus else [],
                )

                if player.country_flag is None:
                    country_code = (
                        player.iplookup.geolite2.country_code
                        if player.iplookup.geolite2.country_code not in ['...', 'N/A']
                        else player.iplookup.ipapi.country_code
                        if player.iplookup.ipapi.country_code not in ['...', 'N/A']
                        else None
                    )
                    if (
                        country_code
                        and (flag_path := COUNTRY_FLAGS_FOLDER_PATH / f'{country_code.upper()}.png').exists()
                    ):
                        pixmap = QPixmap()
                        pixmap.loadFromData(flag_path.read_bytes())
                        player.country_flag = PlayerCountryFlag(
                            pixmap=pixmap,
                            icon=QIcon(pixmap),
                        )

                if not player.iplookup.geolite2.is_initialized:
                    player.iplookup.geolite2.country, player.iplookup.geolite2.country_code = get_country_info(player.ip)
                    player.iplookup.geolite2.city = get_city_info(player.ip)
                    player.iplookup.geolite2.asn = get_asn_info(player.ip)
                    player.iplookup.geolite2.is_initialized = True

                if player in session_connected:
                    if (
                        player.iplookup.ipapi.mobile is True
                        and GUIDetectionSettings.mobile_detection_enabled
                        and not MobileWarnings.is_ip_notified(player.ip)
                        and MobileWarnings.add_notified_ip(player.ip)
                    ):
                        show_detection_warning_popup(player, 'mobile')

                    if (
                        player.iplookup.ipapi.proxy is True
                        and GUIDetectionSettings.vpn_detection_enabled
                        and not VPNWarnings.is_ip_notified(player.ip)
                        and VPNWarnings.add_notified_ip(player.ip)
                    ):
                        show_detection_warning_popup(player, 'vpn')

                    if (
                        player.iplookup.ipapi.hosting is True
                        and GUIDetectionSettings.hosting_detection_enabled
                        and not HostingWarnings.is_ip_notified(player.ip)
                        and HostingWarnings.add_notified_ip(player.ip)
                    ):
                        show_detection_warning_popup(player, 'hosting')

            if Settings.CAPTURE_PROGRAM_PRESET == 'GTA5':
                if SessionHost.player and SessionHost.player.left_event.is_set():
                    SessionHost.player = None
                # TODO(BUZZARDGTA): We should also potentially needs to check that not more then 1s passed before each disconnected
                if SessionHost.players_pending_for_disconnection and all(player.left_event.is_set() for player in SessionHost.players_pending_for_disconnection):
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection.clear()

                if not session_connected:
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection.clear()
                elif len(session_connected) >= 1 and all(not player.pps.is_first_calculation and not player.pps.rate for player in session_connected):
                    SessionHost.players_pending_for_disconnection = session_connected
                elif SessionHost.search_player:
                    SessionHost.get_host_player(session_connected)

            if Settings.GUI_SESSIONS_LOGGING and (last_session_logging_processing_time is None or (time.monotonic() - last_session_logging_processing_time) >= 1.0):
                last_session_logging_processing_time = time.monotonic()
                process_session_logging()

            if Settings.DISCORD_PRESENCE and discord_rpc_manager is not None and (discord_rpc_manager.last_update_time is None or (time.monotonic() - discord_rpc_manager.last_update_time) >= 3.0):  # noqa: PLR2004
                discord_rpc_manager.update(f'{len(session_connected)} player{pluralize(len(session_connected))} connected')

            GUIrenderingData.header_text = generate_gui_header_text(global_pps_rate)
            (
                GUIrenderingData.session_connected_table__num_rows,
                GUIrenderingData.session_connected_table__processed_data,
                GUIrenderingData.session_connected_table__compiled_colors,
                GUIrenderingData.session_disconnected_table__num_rows,
                GUIrenderingData.session_disconnected_table__processed_data,
                GUIrenderingData.session_disconnected_table__compiled_colors,
            ) = process_gui_session_tables_rendering()
            GUIrenderingData.gui_rendering_ready_event.set()

            gui_closed__event.wait(1)


clear_screen()
set_window_title(f'DEBUG CONSOLE - {TITLE}')

rendering_core__thread = Thread(target=rendering_core, name='rendering_core', daemon=True)
rendering_core__thread.start()

hostname_core__thread = Thread(target=hostname_core, name='hostname_core', daemon=True)
hostname_core__thread.start()

iplookup_core__thread = Thread(target=iplookup_core, name='iplookup_core', daemon=True)
iplookup_core__thread.start()

pinger_core__thread = Thread(target=pinger_core, name='pinger_core', daemon=True)
pinger_core__thread.start()

capture_core__thread = Thread(target=capture_core, name='capture_core', daemon=True)
capture_core__thread.start()


class SessionTableModel(QAbstractTableModel):
    TABLE_CELL_TOOLTIP_MARGIN = 8  # Margin in pixels for determining when to show tooltips for truncated text

    def __init__(self, headers: list[str]) -> None:
        super().__init__()

        self._view: SessionTableView | None = None  # Initially, no view is attached
        self._data: list[list[str]] = []  # The data to be displayed in the table
        self._compiled_colors: list[list[CellColor]] = []  # The compiled colors for the table
        self._headers = headers  # The column headers
        self._ip_column_index = self._headers.index('IP Address')
        self._username_column_index = self._headers.index('Usernames')

    # --------------------------------------------------------------------------
    # Public properties
    # --------------------------------------------------------------------------

    @classmethod
    def remove_session_host_crown_from_ip(cls, ip_address: str) -> str:
        """Remove the crown suffix from an IP address string if present.

        The crown emoji (👑) is used to indicate that this IP address belongs to the session host.
        This method removes that visual indicator to get the clean IP address string.

        Args:
            ip_address (str): The IP address string that may contain a session host crown suffix.

        Returns:
            str: The IP address string with session host crown suffix removed.
        """
        return ip_address.removesuffix(' 👑')

    @property
    def view(self) -> 'SessionTableView':
        """Get or attach a `SessionTableView` to this model."""
        if self._view is None:
            raise TypeError(format_type_error(self._view, SessionTableView))
        return self._view

    @view.setter
    def view(self, new_view: 'SessionTableView') -> None:
        """Attach a `SessionTableView` to this model."""
        self._view = new_view

    # --------------------------------------------------------------------------
    # Public read-only properties
    # --------------------------------------------------------------------------

    @property
    def ip_column_index(self) -> int:
        """Returns the index of the 'IP Address' column in this table model.

        This value is computed during initialization based on the `headers` provided.<br>
        It is read-only and specific to this instance.
        """
        return self._ip_column_index

    @property
    def username_column_index(self) -> int:
        """Returns the index of the 'Usernames' column in this table model.

        This value is computed during initialization based on the `headers` provided.<br>
        It is read-only and specific to this instance.
        """
        return self._username_column_index

    # --------------------------------------------------------------------------
    # Qt model methods (overrides)
    # --------------------------------------------------------------------------

    # pylint: disable=invalid-name
    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        if parent is None:
            parent = QModelIndex()
        return len(self._data)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        if parent is None:
            parent = QModelIndex()
        return len(self._headers)
    # pylint: enable=invalid-name

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> str | QBrush | QIcon | None:
        """Override data method to customize data retrieval and alignment."""
        if not index.isValid():
            return None

        row_idx = index.row()
        col_idx = index.column()

        # Check bounds
        if row_idx >= len(self._data) or col_idx >= len(self._data[row_idx]):
            return None  # Return None for invalid index

        if role == Qt.ItemDataRole.DecorationRole:  # noqa: SIM102
            if self.get_column_index_by_name('Country') == col_idx:
                ip = self.get_ip_from_data_safely(self._data[row_idx])

                player = PlayersRegistry.require_player_by_ip(ip)
                if player.country_flag is not None:
                    return player.country_flag.icon

        if role == Qt.ItemDataRole.DisplayRole:
            # Return the cell's text
            return self._data[row_idx][col_idx]

        if role == Qt.ItemDataRole.ForegroundRole:  # noqa: SIM102
            # Return the cell's foreground color
            if row_idx < len(self._compiled_colors) and col_idx < len(self._compiled_colors[row_idx]):
                return QBrush(self._compiled_colors[row_idx][col_idx].foreground)

        if role == Qt.ItemDataRole.BackgroundRole:  # noqa: SIM102
            # Return the cell's background color
            if row_idx < len(self._compiled_colors) and col_idx < len(self._compiled_colors[row_idx]):
                return QBrush(self._compiled_colors[row_idx][col_idx].background)

        if role == Qt.ItemDataRole.ToolTipRole:
            # Return the tooltip text for the cell
            view = self.view
            horizontal_header = view.horizontalHeader()
            resize_mode = horizontal_header.sectionResizeMode(index.column())

            # Return None if the column resize mode isn't set to Stretch, as it shouldn't be truncated
            if resize_mode != QHeaderView.ResizeMode.Stretch:
                return None

            cell_text = self._data[row_idx][col_idx]

            font_metrics = view.fontMetrics()
            text_width = font_metrics.horizontalAdvance(cell_text)
            column_width = view.columnWidth(index.column())

            if text_width > column_width - self.TABLE_CELL_TOOLTIP_MARGIN:
                return cell_text

        return None

    # pylint: disable=invalid-name
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> str | None:  # noqa: N802
        from modules.constants.standalone import GUI_COLUMN_HEADERS_TOOLTIPS

        if orientation == Qt.Orientation.Horizontal:
            if role == Qt.ItemDataRole.DisplayRole:
                return self._headers[section]  # Display the header name
            if role == Qt.ItemDataRole.ToolTipRole:
                # Fetch the header name and return the corresponding tooltip
                header_name = self._headers[section]
                return GUI_COLUMN_HEADERS_TOOLTIPS.get(header_name, None)

        return None
    # pylint enable=invalid-name

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        """Sort the table by a specific column.

        Args:
            column: The column index to sort by.
            order: The order (ascending/descending) to sort in.
        """
        if not self._data:
            if self._compiled_colors:
                raise TableDataConsistencyError(case='colors_without_data')
            return  # No data to process, exit early.

        if not self._compiled_colors:
            raise TableDataConsistencyError(case='data_without_colors')

        self.layoutAboutToBeChanged.emit()

        sorted_column_name = self._headers[column]

        # Combine data and colors for sorting
        combined = list(zip(self._data, self._compiled_colors, strict=True))
        if not combined:
            raise TableDataConsistencyError(case='empty_combined')
        sort_order_bool = order == Qt.SortOrder.DescendingOrder

        if sorted_column_name == 'Usernames':
            combined.sort(
                key=lambda row: ', '.join(row[0][column]).casefold(),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {'First Seen', 'Last Rejoin', 'Last Seen'}:
            # Retrieve the player datetime object from the IP column
            def extract_datetime_for_ip(ip: str) -> datetime:
                """Extract a datetime object for a given IP address."""
                player = PlayersRegistry.require_player_by_ip(ip)

                # Retrieve the player datetime attribute name for the selected column
                # Mapping column names to player datetime attributes
                datetime_attribute = {
                    'First Seen': 'first_seen',
                    'Last Rejoin': 'last_rejoin',
                    'Last Seen': 'last_seen',
                }.get(self._headers[column])
                if datetime_attribute is None:
                    raise TypeError(format_type_error(datetime_attribute, str))

                player_datetime = getattr(player.datetime, datetime_attribute, None)
                if not isinstance(player_datetime, datetime):
                    raise TypeError(format_type_error(player_datetime, datetime))
                return player_datetime

            combined.sort(
                key=lambda row: extract_datetime_for_ip(self.get_ip_from_data_safely(row[0])),
                reverse=not sort_order_bool,
            )
        elif sorted_column_name == 'IP Address':
            # Sort by IP address
            import ipaddress

            combined.sort(
                key=lambda row: ipaddress.ip_address(self.get_ip_from_data_safely(row[0])),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {'Rejoins', 'T. Packets', 'Packets', 'PPS', 'PPM', 'Last Port', 'First Port'}:
            # Sort by integer/float value of the column value
            combined.sort(
                key=lambda row: float(row[0][column]),
                reverse=sort_order_bool,
            )
        elif sorted_column_name == 'Middle Ports':
            # Sort by the number of ports in the list (length)
            combined.sort(
                key=lambda row: len(row[0][column]),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {'Lat', 'Lon', 'Offset'}:
            # Sort by integer/float value of the column value but keep "..." at the end
            combined.sort(
                key=lambda row: float(row[0][column]) if row[0][column] != '...' else float('-inf'),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {'Hostname', 'Continent', 'Country', 'Region', 'R. Code', 'City', 'District', 'ZIP Code', 'Time Zone', 'Currency', 'Organization', 'ISP', 'ASN / ISP', 'AS', 'ASN'}:
            # Sort by string representation of the column value
            combined.sort(
                key=lambda row: str(row[0][column]).casefold(),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {'Mobile', 'VPN', 'Hosting', 'Pinging'}:
            # Sort by boolean representation of the column value
            combined.sort(
                key=lambda row: str(row[0][column]).casefold(),
                reverse=sort_order_bool,
            )
        else:
            raise UnsupportedSortColumnError(sorted_column_name)

        # Unpack the sorted data
        self._data, self._compiled_colors = map(list, zip(*combined, strict=True))

        self.layoutChanged.emit()
    # pylint: enable=invalid-name

    # --------------------------------------------------------------------------
    # Custom / internal management methods
    # --------------------------------------------------------------------------

    def get_column_index_by_name(self, column_name: str, /) -> int:
        """Get the table index of a specified column.

        Args:
            column_name: The column name to look for.

        Returns:
            The table column index.
        """
        return self._headers.index(column_name)

    def get_row_index_by_ip(self, ip: str, /) -> int | None:
        """Find the row index for the given IP address.

        Args:
            ip: The IP address to search for.

        Returns:
            The index of the row containing the IP address, or None if not found.
        """
        for row_index, row_data in enumerate(self._data):
            if self.get_ip_from_data_safely(row_data) == ip:
                return row_index
        return None

    def get_ip_from_data_safely(self, row_data: list[str]) -> str:
        """Safely extract an IP address as a string from row data.

        This method ensures the IP address is always returned as a string type.

        Args:
            row_data (list[str]): The row data list containing the IP address.

        Returns:
            The IP address as a clean string (with crown suffix removed if present).

        Raises:
            IndexError: If the IP column index is out of bounds.
            TypeError: If the IP data is not a string.
        """
        if self.ip_column_index >= len(row_data):
            error_msg = f'IP column index {self.ip_column_index} is out of bounds for row data with {len(row_data)} columns'
            raise IndexError(error_msg)

        ip_data = row_data[self.ip_column_index]

        return self.remove_session_host_crown_from_ip(ip_data)

    def get_display_text(self, index: QModelIndex) -> str | None:
        """Extract display text as a string from model data.

        This method handles the case where model data might return `str`, `QBrush`, `QIcon` or `None` for decoration roles, but we only want the display text as a string.<br>
        For 'IP Address' column, it automatically removes the session host crown suffix (👑) if present.

        Args:
            index (QModelIndex): The QModelIndex to get display text from.

        Returns:
            The display text as a string, or `None` if no valid display text is available.
            For the 'IP Address' column, the crown suffix is automatically removed.

        Raises:
            TypeError: If the display data is not a string and is not `None`.
        """
        # Explicitly request DisplayRole to get only the text content
        display_data = self.data(index, Qt.ItemDataRole.DisplayRole)
        if display_data is None:
            return None
        if not isinstance(display_data, str):
            raise TypeError(format_type_error(display_data, str))

        # If this is an IP Address column, remove the crown suffix
        if index.column() == self.ip_column_index:
            return self.remove_session_host_crown_from_ip(display_data)

        return display_data

    def sort_current_column(self) -> None:
        """Call the sort method with the current column index and order.

        Ensures sorting reflects the current state of the header.
        """
        # Retrieve the current sort column and order
        horizontal_header = self.view.horizontalHeader()
        sort_column = horizontal_header.sortIndicatorSection()
        sort_order = horizontal_header.sortIndicatorOrder()

        # Call the sort function with the retrieved arguments
        self.sort(sort_column, sort_order)

    def add_row_without_refresh(self, row_data: list[str], row_colors: list[CellColor]) -> None:
        """Add a new row to the model without notifying the view in real time.

        Args:
            row_data: The data for the new row.
            row_colors: A list of `CellColor` objects corresponding to the row's colors.
        """
        # Only update internal data without triggering signals
        self._data.append(row_data)
        self._compiled_colors.append(row_colors)

    def update_row_without_refresh(self, row_index: int, row_data: list[str], row_colors: list[CellColor]) -> None:
        """Update an existing row in the model with new data and colors without notifying the view in real time.

        Args:
            row_index: The index of the row to update.
            row_data: The new data for the row.
            row_colors: A list of `CellColor` objects corresponding to the row's colors.
        """
        if 0 <= row_index < self.rowCount():
            self._data[row_index] = row_data
            self._compiled_colors[row_index] = row_colors

    def delete_row(self, row_index: int) -> None:
        """Delete a row from the model along with its associated colors.

        If any items are selected under this row, their selection moves one row up.

        Args:
            row_index: The index of the row to delete.
        """
        if 0 <= row_index < self.rowCount():
            view = self.view
            selection_model = view.selectionModel()

            # Adjust selection for the deleted row
            for index in selection_model.selection().indexes():
                if index.row() == row_index:  # Row to be deleted
                    # Deselect the row because it's about to be deleted
                    # Select the row to be deleted
                    selection = QItemSelection(
                        self.index(index.row(), index.column()),
                        self.index(index.row(), index.column()),
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
                        self.index(index.row(), index.column()),
                    )
                    selection_model.select(selection_to_deselect, QItemSelectionModel.SelectionFlag.Deselect)

                    # Move the selection up by one row
                    selection_to_select = QItemSelection(
                        self.index(index.row() - 1, index.column()),  # New row after deletion
                        self.index(index.row() - 1, index.column()),
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

            # Ensure the view resizes properly after a row is removed
            #view.resizeRowsToContents()
            #view.viewport().update()

    def refresh_view(self) -> None:
        """Notifies the view to refresh and reflect all changes made to the model."""
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()


class SessionTableView(QTableView):
    def __init__(self, model: SessionTableModel, sort_column: int, sort_order: Qt.SortOrder) -> None:
        super().__init__()

        self._drag_selecting: bool = False  # Track if the mouse is being dragged with Ctrl key
        self._previous_cell: QModelIndex | None = None  # Track the previously selected cell
        self._previous_sort_section_index: int | None = None

        self.setModel(model)
        self.setMouseTracking(True)  # Track mouse without clicks
        viewport = self.viewport()
        viewport.installEventFilter(self)  # Install event filter
        # Configure table view settings
        vertical_header = self.verticalHeader()
        vertical_header.setVisible(False)  # Hide row index
        self.setAlternatingRowColors(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        horizontal_header = self.horizontalHeader()
        horizontal_header.setSectionsClickable(True)
        horizontal_header.sectionClicked.connect(self.on_section_clicked)  # pyright: ignore[reportUnknownMemberType]
        horizontal_header.setSectionsMovable(True)
        self.setSelectionMode(QTableView.SelectionMode.NoSelection)
        self.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)
        self.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)

        # Set the sort indicator for the specified column
        self.setSortingEnabled(False)
        horizontal_header.setSortIndicator(sort_column, sort_order)
        horizontal_header.setSortIndicatorShown(True)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)  # pyright: ignore[reportUnknownMemberType]

    # pylint: disable=invalid-name
    def setModel(self, model: QAbstractItemModel | None) -> None:  # noqa: N802
        """Override the setModel method to ensure the model is of type SessionTableModel."""
        if not isinstance(model, SessionTableModel):
            raise TypeError(format_type_error(model, SessionTableModel))
        super().setModel(model)

    def model(self) -> SessionTableModel:
        """Override the model method to ensure it returns a SessionTableModel."""
        model = super().model()
        if not isinstance(model, SessionTableModel):
            raise TypeError(format_type_error(model, SessionTableModel))
        return model

    def selectionModel(self) -> QItemSelectionModel:  # noqa: N802
        """Override the selectionModel method to ensure it returns a QItemSelectionModel."""
        selection_model = super().selectionModel()
        if not isinstance(selection_model, QItemSelectionModel):
            raise TypeError(format_type_error(selection_model, QItemSelectionModel))
        return selection_model

    def viewport(self) -> QWidget:
        """Override the viewport method to ensure it returns a QWidget."""
        viewport = super().viewport()
        if not isinstance(viewport, QWidget):
            raise TypeError(format_type_error(viewport, QWidget))
        return viewport

    def verticalHeader(self) -> QHeaderView:  # noqa: N802
        """Override the verticalHeader method to ensure it returns a QHeaderView."""
        header = super().verticalHeader()
        if not isinstance(header, QHeaderView):
            raise TypeError(format_type_error(header, QHeaderView))
        return header

    def horizontalHeader(self) -> QHeaderView:  # noqa: N802
        """Override the horizontalHeader method to ensure it returns a QHeaderView."""
        header = super().horizontalHeader()
        if not isinstance(header, QHeaderView):
            raise TypeError(format_type_error(header, QHeaderView))
        return header

    def eventFilter(self, object: QObject | None, event: QEvent | None) -> bool:  # pylint: disable=redefined-builtin  # noqa: A002, N802
        if isinstance(object, QWidget) and isinstance(event, QHoverEvent):
            index = self.indexAt(event.position().toPoint())  # Get hovered cell
            if index.isValid():
                model = self.model()

                if model.get_column_index_by_name('Country') == index.column():
                    ip = model.get_display_text(model.index(index.row(), model.ip_column_index))
                    if ip is not None:
                        player = PlayersRegistry.require_player_by_ip(ip)
                        if player.country_flag is not None:
                            self.show_flag_tooltip(event, index, player)

        return super().eventFilter(object, event)

    def keyPressEvent(self, e: QKeyEvent | None) -> None:  # noqa: N802
        """Handle key press events to capture Ctrl+A for selecting all and Ctrl+C for copying selected data to the clipboard.

        Fall back to default behavior for other key presses.
        """
        if isinstance(e, QKeyEvent):  # noqa: SIM102
            if e.modifiers() == Qt.KeyboardModifier.ControlModifier:
                if e.key() == Qt.Key.Key_A:
                    self.select_all_cells()
                elif e.key() == Qt.Key.Key_C:
                    self.copy_selected_cells(self.model(), self.selectionModel().selectedIndexes())
                return

        # Fall back to default behavior
        super().keyPressEvent(e)

    def mousePressEvent(self, e: QMouseEvent | None) -> None:  # noqa: N802
        """Handle mouse press events for selecting multiple items with Ctrl or single items otherwise.

        Fall back to default behavior for non-cell areas.
        """
        if isinstance(e, QMouseEvent):
            index = self.indexAt(e.pos())  # Determine the index of the clicked item
            if index.isValid():
                selection_model = self.selectionModel()
                selection_flag = None

                if e.button() == Qt.MouseButton.LeftButton:
                    if e.modifiers() == Qt.KeyboardModifier.ControlModifier:
                        selection_flag = (
                            QItemSelectionModel.SelectionFlag.Deselect
                            if selection_model.isSelected(index)
                            else QItemSelectionModel.SelectionFlag.Select
                        )
                        self._drag_selecting = True
                        self._previous_cell = index
                    elif e.modifiers() == Qt.KeyboardModifier.NoModifier:
                        was_selection_index_selected = selection_model.isSelected(index)
                        selection_model.clearSelection()
                        selection_flag = (
                            QItemSelectionModel.SelectionFlag.Deselect
                            if was_selection_index_selected
                            else QItemSelectionModel.SelectionFlag.Select
                        )

                elif e.button() == Qt.MouseButton.RightButton:  # noqa: SIM102
                    if not selection_model.isSelected(index):
                        selection_flag = QItemSelectionModel.SelectionFlag.ClearAndSelect

                if selection_flag is not None:
                    selection_model.select(index, selection_flag)

        # Fall back to default behavior
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e: QMouseEvent | None) -> None:  # noqa: N802
        """Handle mouse movement during Ctrl + Left-Click drag to toggle the selection of multiple cells."""
        if isinstance(e, QMouseEvent):
            index = self.indexAt(e.pos())  # Get the index under the cursor
            if index.isValid():
                selection_model = self.selectionModel()

                if e.buttons() == Qt.MouseButton.LeftButton:  # noqa: SIM102
                    if e.modifiers() == Qt.KeyboardModifier.ControlModifier:  # noqa: SIM102
                        if self._drag_selecting and self._previous_cell != index:
                            self._previous_cell = index

                            selection_model.select(index, (
                                QItemSelectionModel.SelectionFlag.Deselect
                                if selection_model.isSelected(index)
                                else QItemSelectionModel.SelectionFlag.Select
                            ))

        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e: QMouseEvent | None) -> None:  # noqa: N802
        """Reset dragging state when the mouse button is released."""
        if isinstance(e, QMouseEvent):  # noqa: SIM102
            if e.button() == Qt.MouseButton.LeftButton:
                self._drag_selecting = False
                self._previous_cell = None

        super().mouseReleaseEvent(e)
    # pylint: enable=invalid-name

    # --------------------------------------------------------------------------
    # Custom / internal management methods
    # --------------------------------------------------------------------------

    def setup_static_column_resizing(self) -> None:
        """Set up static column resizing for the table."""
        model = self.model()
        horizontal_header = self.horizontalHeader()

        for column in range(model.columnCount()):
            header_label = model.headerData(column, Qt.Orientation.Horizontal)

            if header_label in {'First Seen', 'Last Rejoin', 'Last Seen', 'Rejoins', 'T. Packets', 'Packets', 'PPS', 'PPM',
                                'IP Address', 'First Port', 'Last Port', 'Mobile', 'VPN', 'Hosting', 'Pinging',
                                'R. Code', 'ZIP Code', 'Lat', 'Lon', 'Offset', 'Currency', 'Time Zone'}:
                horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
            else:
                horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)

    def adjust_username_column_width(self) -> None:
        """Adjust the 'Usernames' column width based on whether any username is non-empty."""
        model = self.model()
        header = self.horizontalHeader()

        found_username = False
        for row in range(model.rowCount()):
            index = model.index(row, model.username_column_index)
            data = model.get_display_text(index)
            if data and data.strip():  # Check for non-empty, non-whitespace
                found_username = True
                break

        if found_username:
            header.setSectionResizeMode(model.username_column_index, QHeaderView.ResizeMode.Stretch)
        else:
            header.setSectionResizeMode(model.username_column_index, QHeaderView.ResizeMode.ResizeToContents)

    def get_sorted_column(self) -> tuple[str, Qt.SortOrder]:
        """Get the currently sorted column and its order for this table view."""
        model = self.model()
        horizontal_header = self.horizontalHeader()

        # Get the index of the currently sorted column
        sorted_column_index = horizontal_header.sortIndicatorSection()

        # Get the sort order (ascending or descending)
        sort_order = horizontal_header.sortIndicatorOrder()

        # Get the name of the sorted column from the model
        sorted_column_name = model.headerData(sorted_column_index, Qt.Orientation.Horizontal)
        if sorted_column_name is None:
            raise TypeError(format_type_error(sorted_column_name, str))

        return sorted_column_name, sort_order

    def handle_menu_hovered(self, action: QAction) -> None:
        # Fixes: https://stackoverflow.com/questions/21725119/why-wont-qtooltips-appear-on-qactions-within-a-qmenu
        action_parent = action.parent()
        if isinstance(action_parent, QMenu):
            action_parent.setToolTip(action.toolTip())

    def on_section_clicked(self, section_index: int) -> None:
        model = self.model()
        horizontal_header = self.horizontalHeader()
        selection_model = self.selectionModel()

        # Clear selections when a header section is clicked
        selection_model.clearSelection()

        # If it's the first click or sorting is being toggled
        if self._previous_sort_section_index is None or self._previous_sort_section_index != section_index:
            horizontal_header.setSortIndicator(section_index, Qt.SortOrder.DescendingOrder)

        # Sort the model
        model.sort(section_index, horizontal_header.sortIndicatorOrder())
        self._previous_sort_section_index = section_index

    def show_flag_tooltip(self, event: QHoverEvent, index: QModelIndex, player: Player) -> None:
        """Show tooltip only if hovering exactly over the flag."""
        # TODO(BUZZARDGTA): Make the tooltip appear precisely when hovering over the flag, using the pixmap or QIcon object if possible.
        cell_rect = self.visualRect(index)   # Get cell rectangle
        flag_x_start = cell_rect.left() + 4  # Assuming flag starts with a 4px horizontal padding
        flag_x_end = flag_x_start + 14       # Assuming flag ends with a 14px horizontal padding
        flag_y_start = cell_rect.top() + 10  # Assuming flag starts with a 10px vertical padding
        flag_y_end = flag_y_start + 10       # Assuming flag ends with a 10px vertical padding
        # Check if the mouse is over the flag both horizontally and vertically
        if flag_x_start <= event.position().toPoint().x() <= flag_x_end and flag_y_start <= event.position().toPoint().y() <= flag_y_end:
            QToolTip.showText(event.globalPosition().toPoint(), player.iplookup.geolite2.country, self)
        else:
            QToolTip.hideText()

    def show_context_menu(self, pos: QPoint) -> None:
        """Show the context menu at the specified position with options to interact with the table's content."""
        from modules.constants.standard import (
            USERIP_DATABASES_PATH,
        )

        def add_action(
            menu: QMenu,
            label: str,
            shortcut: str | None = None,
            tooltip: str | None = None,
            handler: Callable[..., None] | None = None,
            *,
            enabled: bool | None = None,
        ):
            """Helper to create and configure a QAction."""
            action = menu.addAction(label)  # pyright: ignore[reportUnknownMemberType]
            if not isinstance(action, QAction):
                raise TypeError(format_type_error(action, QAction))

            if shortcut:
                action.setShortcut(shortcut)
            if tooltip:
                action.setToolTip(tooltip)
            if enabled is False:
                action.setEnabled(enabled)
            elif handler:
                action.triggered.connect(handler)  # pyright: ignore[reportUnknownMemberType]

            return action

        def add_menu(parent_menu: QMenu, label: str, tooltip: str | None = None) -> QMenu:
            """Helper to create and configure a QMenu."""
            menu = parent_menu.addMenu(label)
            if not isinstance(menu, QMenu):
                raise TypeError(format_type_error(menu, QMenu))

            if tooltip:
                menu.setToolTip(tooltip)

            return menu

        # Determine the index at the clicked position
        index = self.indexAt(pos)
        if not index.isValid():
            return  # Do nothing if the click is outside valid cells

        selected_model = self.model()
        selection_model = self.selectionModel()
        selected_indexes = selection_model.selectedIndexes()

        # Create the main context menu
        context_menu = QMenu(self)
        context_menu.setStyleSheet(CUSTOM_CONTEXT_MENU_STYLESHEET)
        context_menu.setToolTipsVisible(True)
        context_menu.hovered.connect(self.handle_menu_hovered)  # pyright: ignore[reportUnknownMemberType]

        # Add "Copy Selection" action
        add_action(
            context_menu,
            'Copy Selection',
            shortcut='Ctrl+C',
            tooltip='Copy selected cells to your clipboard.',
            handler=lambda: self.copy_selected_cells(selected_model, selected_indexes),
        )
        context_menu.addSeparator()

        # "Select" submenu
        select_menu = add_menu(context_menu, 'Select  ')
        add_action(
            select_menu,
            'Select All',
            shortcut='Ctrl+A',
            tooltip='Select all cells in the table.',
            handler=self.select_all_cells,
        )
        add_action(
            select_menu,
            'Select Row',
            tooltip='Select all cells in this row.',
            handler=lambda: self.select_row_cells(index.row()),
        )
        add_action(
            select_menu,
            'Select Column',
            tooltip='Select all cells in this column.',
            handler=lambda: self.select_column_cells(index.column()),
        )

        # "Unselect" submenu
        unselect_menu = add_menu(context_menu, 'Unselect')
        add_action(
            unselect_menu,
            'Unselect All',
            tooltip='Unselect all cells in the table.',
            handler=self.unselect_all_cells,
        )
        add_action(
            unselect_menu,
            'Unselect Row',
            tooltip='Unselect all cells in this row.',
            handler=lambda: self.unselect_row_cells(index.row()),
        )
        add_action(
            unselect_menu,
            'Unselect Column',
            tooltip='Unselect all cells in this column.',
            handler=lambda: self.unselect_column_cells(index.column()),
        )
        context_menu.addSeparator()

        # Process if one cell is selected
        if len(selected_indexes) == 1:
            selected_column = selected_indexes[0].column()

            column_name = selected_model.headerData(selected_column, Qt.Orientation.Horizontal)
            if not isinstance(column_name, str):
                raise TypeError(format_type_error(column_name, str))

            if column_name == 'IP Address':
                from modules.constants.local import SCRIPTS_FOLDER_PATH

                # Get the IP address from the selected cell
                displayed_ip = selected_model.get_display_text(selected_indexes[0])
                if not displayed_ip:
                    return

                userip_database_filepaths = UserIPDatabases.get_userip_database_filepaths()
                player = PlayersRegistry.require_player_by_ip(displayed_ip)

                add_action(
                    context_menu,
                    'IP Lookup Details',
                    tooltip='Displays a notification with a detailed IP lookup report for selected player.',
                    handler=lambda: self.show_detailed_ip_lookup_player_cell(displayed_ip),
                )

                ping_menu = add_menu(context_menu, 'Ping    ')
                add_action(
                    ping_menu,
                    'Normal',
                    tooltip='Checks if selected IP address responds to pings.',
                    handler=lambda: self.ping(displayed_ip),
                )
                add_action(
                    ping_menu,
                    'TCP Port (paping.exe)',
                    tooltip='Checks if selected IP address responds to TCP pings on a given port.',
                    handler=lambda: self.tcp_port_ping(displayed_ip),
                )

                scripts_menu = add_menu(context_menu, 'User Scripts ')
                for script in SCRIPTS_FOLDER_PATH.glob('*'):
                    if (
                        not script.is_file()
                        or script.name.startswith(('_', '.'))
                        or script.suffix.casefold() not in {'.bat', '.cmd', '.exe', '.py', '.lnk'}
                    ):
                        continue

                    script_resolved = script.resolve()

                    def create_script_handler(script_path: Path) -> Callable[[], None]:
                        return lambda: run_cmd_script(script_path, [displayed_ip])  # type: ignore[list-item]

                    add_action(
                        scripts_menu,
                        script_resolved.name,
                        tooltip='',
                        handler=create_script_handler(script_resolved),
                    )

                userip_menu = add_menu(context_menu, 'UserIP  ')

                if player.userip is None:
                    add_userip_menu = add_menu(userip_menu, 'Add     ', 'Add selected IP address to UserIP database.')  # Extra spaces for alignment
                    for database_path in userip_database_filepaths:
                        def create_add_handler(db_path: Path) -> Callable[[], None]:
                            return lambda: self.userip_manager__add([displayed_ip], db_path)  # type: ignore[list-item]

                        add_action(
                            add_userip_menu,
                            str(database_path.relative_to(USERIP_DATABASES_PATH).with_suffix('')),
                            tooltip='Add selected IP address to this UserIP database.',
                            handler=create_add_handler(database_path),
                        )
                else:
                    move_userip_menu = add_menu(userip_menu, 'Move    ', 'Move selected IP address to another database.')
                    for database_path in userip_database_filepaths:
                        def create_move_handler(db_path: Path) -> Callable[[], None]:
                            return lambda: self.userip_manager__move([displayed_ip], db_path)  # type: ignore[list-item]

                        add_action(
                            move_userip_menu,
                            str(database_path.relative_to(USERIP_DATABASES_PATH).with_suffix('')),
                            tooltip='Move selected IP address to this UserIP database.',
                            handler=create_move_handler(database_path),
                            enabled=player.userip.database_path != database_path,
                        )
                    add_action(
                        userip_menu,
                        'Delete  ',  # Extra spaces for alignment
                        tooltip='Delete selected IP address from UserIP databases.',
                        handler=lambda: self.userip_manager__del([displayed_ip]),  # type: ignore[list-item]
                    )

        # Check if all selected cells are in the "IP Address" column
        elif all(
            selected_model.headerData(index.column(), Qt.Orientation.Horizontal) == 'IP Address'
            for index in selected_indexes
        ):
            all_ips: list[str] = []

            # Get the IP addresses from the selected cells
            for index in selected_indexes:
                displayed_ip = selected_model.get_display_text(index)
                if displayed_ip:
                    all_ips.append(displayed_ip)

            if all(ip not in UserIPDatabases.ips_set for ip in all_ips):
                userip_menu = add_menu(context_menu, 'UserIP  ')

                add_userip_menu = add_menu(userip_menu, 'Add Selected')
                for database_path in UserIPDatabases.get_userip_database_filepaths():
                    def create_multi_add_handler(db_path: Path, ip_list: list[str]) -> Callable[[], None]:
                        return lambda: self.userip_manager__add(ip_list, db_path)

                    add_action(
                        add_userip_menu,
                        str(database_path.relative_to(USERIP_DATABASES_PATH).with_suffix('')),
                        tooltip='Add selected IP addresses to this UserIP database.',
                        handler=create_multi_add_handler(database_path, all_ips),
                    )
            elif all(ip in UserIPDatabases.ips_set for ip in all_ips):
                userip_menu = add_menu(context_menu, 'UserIP  ')

                move_userip_menu = add_menu(userip_menu, 'Move Selected')
                for database_path in UserIPDatabases.get_userip_database_filepaths():
                    def create_multi_move_handler(db_path: Path, ip_list: list[str]) -> Callable[[], None]:
                        return lambda: self.userip_manager__move(ip_list, db_path)

                    add_action(
                        move_userip_menu,
                        str(database_path.relative_to(USERIP_DATABASES_PATH).with_suffix('')),
                        tooltip='Move selected IP addresses to this UserIP database.',
                        handler=create_multi_move_handler(database_path, all_ips),
                    )

                add_action(
                    userip_menu,
                    'Delete Selected',  # Extra spaces for alignment
                    tooltip='Delete selected IP addresses from UserIP databases.',
                    handler=lambda: self.userip_manager__del(all_ips),
                )

        # Execute the context menu at the right-click position
        context_menu.exec(self.mapToGlobal(pos))  # pyright: ignore[reportUnknownMemberType]

    def copy_selected_cells(self, selected_model: SessionTableModel, selected_indexes: list[QModelIndex]) -> None:
        """Copy the selected cells data from the table to the clipboard."""
        # Access the system clipboard from the centralized app instance
        clipboard = app.clipboard()
        if not isinstance(clipboard, QClipboard):
            raise TypeError(format_type_error(clipboard, QClipboard))

        # Prepare a list to store text data from selected cells
        selected_texts: list[str] = []

        # Iterate over each selected index and retrieve its display data
        for index in selected_indexes:
            cell_text = selected_model.get_display_text(index)
            if cell_text is None:
                continue  # Skip if no valid display text is available

            selected_texts.append(cell_text)

        # Return if no text was selected
        if not selected_texts:
            return

        # Join all selected text entries with a newline to format for copying
        clipboard_content = '\n'.join(selected_texts)

        # Set the formatted text in the system clipboard
        clipboard.setText(clipboard_content)

    def show_detailed_ip_lookup_player_cell(self, ip: str) -> None:
        from modules.constants.standard import USERIP_DATABASES_PATH

        player = PlayersRegistry.require_player_by_ip(ip)

        QMessageBox.information(self, TITLE, format_triple_quoted_text(f"""
            ############ Player Infos #############
            IP Address: {player.ip}
            Hostname: {player.reverse_dns.hostname}
            Username{pluralize(len(player.usernames))}: {', '.join(player.usernames) or ""}
            In UserIP database: {(player.userip_detection is not None and f"{player.userip and player.userip.database_path.relative_to(USERIP_DATABASES_PATH).with_suffix('')}") or "No"}
            Last Port: {player.ports.last}
            Middle Port{pluralize(len(player.ports.middle))}: {', '.join(map(str, player.ports.middle))}
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
            AS: {player.iplookup.ipapi.asn}
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
        """),
        )

    def ping(self, ip: str) -> None:
        """Runs a continuous ping to a specified IP address in a new terminal window."""
        run_cmd_command('ping', [ip, '-t'])

    def tcp_port_ping(self, ip: str) -> None:
        """Runs paping to check TCP connectivity to a host on a user-specified port indefinitely."""

        def run_paping(host: str, port: int) -> None:
            """Runs paping in a new terminal window to check TCP connectivity continuously."""
            from modules.constants.local import PAPING_PATH

            run_cmd_script(PAPING_PATH, [host, '-p', str(port)])

        from modules.constants.standalone import MAX_PORT, MIN_PORT

        port_str, ok = QInputDialog.getText(self, 'Input Port', 'Enter the port number to check TCP connectivity:')

        if not ok:
            return

        port_str = port_str.strip()

        if not port_str.isdigit():
            QMessageBox.warning(self, 'Error', 'No valid port number provided.')
            return

        port = int(port_str)

        if not MIN_PORT <= port <= MAX_PORT:
            QMessageBox.warning(self, 'Error', 'Please enter a valid port number between 1 and 65535.')
            return

        run_paping(ip, port)

    def userip_manager__add(self, ip_addresses: list[str], selected_database: Path) -> None:
        from modules.constants.standard import USERIP_DATABASES_PATH
        from modules.utils import write_lines_to_file

        # Prompt the user for a username
        username, ok = QInputDialog.getText(self, 'Input Username', f'Please enter the username to associate with the selected IP{pluralize(len(ip_addresses))}:')

        if not ok:
            return

        username = username.strip()

        if username:  # Only proceed if the user clicked 'OK' and provided a username
            # Append the username and associated IP(s) to the corresponding database file
            write_lines_to_file(selected_database, 'a', [f'{username}={ip}\n' for ip in ip_addresses])

            QMessageBox.information(self, TITLE, f'Selected IP{pluralize(len(ip_addresses))} {ip_addresses} has been added with username "{username}" to UserIP database "{selected_database.relative_to(USERIP_DATABASES_PATH).with_suffix("")}".')
        else:
            # If the user canceled or left the input empty, show an error
            QMessageBox.warning(self, TITLE, 'ERROR:\nNo username was provided.')

    def userip_manager__move(self, ip_addresses: list[str], selected_database: Path) -> None:
        from modules.constants.standard import (
            RE_USERIP_INI_PARSER_PATTERN,
            USERIP_DATABASES_PATH,
        )
        from modules.utils import write_lines_to_file

        # Dictionary to store removed entries by database
        deleted_entries_by_database: dict[Path, list[str]] = {}

        # Iterate over each UserIP database
        for database_path in UserIPDatabases.get_userip_database_filepaths():
            if database_path == selected_database:
                continue

            # Read the database file
            lines = database_path.read_text(encoding='utf-8').splitlines(keepends=True)
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
                    username, ip = match.group('username').strip(), match.group('ip').strip()

                    # Ensure both username and ip are non-empty strings
                    if isinstance(username, str) and isinstance(ip, str) and ip in ip_addresses:
                        deleted_entries_in_this_database.append(line.strip())  # Store the deleted entry
                        continue

                lines_to_keep.append(line)

            if deleted_entries_in_this_database:
                # Only update the database file if there were any deletions
                write_lines_to_file(database_path, 'w', lines_to_keep)

                # Store the deleted entries for this database
                deleted_entries_by_database[database_path] = deleted_entries_in_this_database

                # Move the deleted entries to the target database
                write_lines_to_file(selected_database, 'a', [f'{entry}\n' for entry in deleted_entries_in_this_database])

        # After processing all databases, show a detailed report
        if deleted_entries_by_database:
            report = f'<b>Selected IP{pluralize(len(ip_addresses))} {ip_addresses} moved from the following UserIP database{pluralize(len(deleted_entries_by_database))} to UserIP database "{selected_database.relative_to(USERIP_DATABASES_PATH).with_suffix("")}":</b><br><br><br>'
            for database_path, deleted_entries in deleted_entries_by_database.items():
                report += f'<b>{database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")}:</b><br>'
                report += '<ul>'
                for entry in deleted_entries:
                    report += f'<li>{entry}</li>'
                report += '</ul><br>'
            report = report.removesuffix('<br>')

            QMessageBox.information(self, TITLE, report)

    def userip_manager__del(self, ip_addresses: list[str]) -> None:
        from modules.constants.standard import (
            RE_USERIP_INI_PARSER_PATTERN,
            USERIP_DATABASES_PATH,
        )
        from modules.utils import write_lines_to_file

        # Dictionary to store removed entries by database
        deleted_entries_by_database: dict[Path, list[str]] = {}

        # Iterate over each UserIP database
        for database_path in UserIPDatabases.get_userip_database_filepaths():
            # Read the database file
            lines = database_path.read_text(encoding='utf-8').splitlines(keepends=True)
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
                    username, ip = match.group('username').strip(), match.group('ip').strip()

                    # Ensure both username and ip are non-empty strings
                    if isinstance(username, str) and isinstance(ip, str) and ip in ip_addresses:
                        deleted_entries_in_this_database.append(line.strip())  # Store the deleted entry
                        continue

                lines_to_keep.append(line)

            if deleted_entries_in_this_database:
                # Only update the database file if there were any deletions
                write_lines_to_file(database_path, 'w', lines_to_keep)

                # Store the deleted entries for this database
                deleted_entries_by_database[database_path] = deleted_entries_in_this_database

        # After processing all databases, show a detailed report
        if deleted_entries_by_database:
            report = f'<b>Selected IP{pluralize(len(ip_addresses))} {ip_addresses} removed from the following UserIP database{pluralize(len(deleted_entries_by_database))}:</b><br><br><br>'
            for database_path, deleted_entries in deleted_entries_by_database.items():
                report += f'<b>{database_path.relative_to(USERIP_DATABASES_PATH).with_suffix("")}:</b><br>'
                report += '<ul>'
                for entry in deleted_entries:
                    report += f'<li>{entry}</li>'
                report += '</ul><br>'
            report = report.removesuffix('<br>')

            QMessageBox.information(self, TITLE, report)

    def _select_all_cells_helper(self, *, select: bool) -> None:
        """Helper function to select or deselect all cells in the table.

        Args:
            select: If True, select all cells; if False, deselect them.
        """
        selected_model = self.model()
        selection_model = self.selectionModel()

        # Early return if no rows exist in the table
        if not selected_model.rowCount():
            return

        # Get the top-left and bottom-right QModelIndex for the entire table
        top_left = selected_model.createIndex(0, 0)  # Top-left item (first row, first column)
        bottom_right = selected_model.createIndex(
            selected_model.rowCount() - 1, selected_model.columnCount() - 1,
        )  # Bottom-right item (last row, last column)

        # Create a selection range from top-left to bottom-right
        selection = QItemSelection(top_left, bottom_right)

        # Use the appropriate selection flag based on the `select` argument
        flag = QItemSelectionModel.SelectionFlag.Select if select else QItemSelectionModel.SelectionFlag.Deselect
        selection_model.select(selection, flag)

    def _select_row_cells_helper(self, row: int, *, select: bool) -> None:
        """Helper function to select or unselect all cells in a specific row.

        Args:
            row: The index of the row to modify selection.
            select: If True, select the row; if False, unselect it.
        """
        selected_model = self.model()
        selection_model = self.selectionModel()

        # Early return if no rows exist in the table
        if not selected_model.rowCount():
            return

        top_index = selected_model.createIndex(row, 0)  # First column of the specified row
        bottom_index = selected_model.createIndex(row, selected_model.columnCount() - 1)  # Last column of the specified row

        # Create a selection range for the entire row
        selection = QItemSelection(top_index, bottom_index)

        # Use the appropriate selection flag based on the `select` argument
        flag = QItemSelectionModel.SelectionFlag.Select if select else QItemSelectionModel.SelectionFlag.Deselect
        selection_model.select(selection, flag)

    def _select_column_cells_helper(self, column: int, *, select: bool) -> None:
        """Helper function to select or unselect all cells in a given column.

        Args:
            column: The index of the column to modify selection.
            select: If True, select the column; if False, unselect it.
        """
        selected_model = self.model()
        selection_model = self.selectionModel()

        # Early return if no rows exist in the table
        if not selected_model.rowCount():
            return

        top_index = selected_model.createIndex(0, column)  # First row of the specified column
        bottom_index = selected_model.createIndex(selected_model.rowCount() - 1, column)  # Last row of the specified column

        # Create a selection range for the entire column
        selection = QItemSelection(top_index, bottom_index)

        # Use the appropriate selection flag based on the `select` argument
        flag = QItemSelectionModel.SelectionFlag.Select if select else QItemSelectionModel.SelectionFlag.Deselect
        selection_model.select(selection, flag)

    def select_all_cells(self) -> None:
        """Select all cells in the table."""
        self._select_all_cells_helper(select=True)

    def unselect_all_cells(self) -> None:
        """Unselect all cells in the table."""
        self._select_all_cells_helper(select=False)

    def select_row_cells(self, row: int) -> None:
        """Select all cells in the specified row."""
        self._select_row_cells_helper(row, select=True)

    def unselect_row_cells(self, row: int) -> None:
        """Unselect all cells in the specified row."""
        self._select_row_cells_helper(row, select=False)

    def select_column_cells(self, column: int) -> None:
        """Select all cells in the specified column."""
        self._select_column_cells_helper(column, select=True)

    def unselect_column_cells(self, column: int) -> None:
        """Unselect all cells in the specified column."""
        self._select_column_cells_helper(column, select=False)


class GUIWorkerThread(QThread):
    update_signal = pyqtSignal(
        str,
        list,
        list,
        int,
        int,
    )

    def __init__(
        self,
        connected_table_view: SessionTableView,
        disconnected_table_view: SessionTableView,
    ):
        super().__init__()

        self.connected_table_view = connected_table_view
        self.disconnected_table_view = disconnected_table_view

    def run(self) -> None:
        while not gui_closed__event.is_set():
            GUIrenderingData.session_connected_sorted_column_name, GUIrenderingData.session_connected_sort_order = self.connected_table_view.get_sorted_column()
            GUIrenderingData.session_disconnected_sorted_column_name, GUIrenderingData.session_disconnected_sort_order = self.disconnected_table_view.get_sorted_column()

            if not GUIrenderingData.gui_rendering_ready_event.is_set():
                continue
            GUIrenderingData.gui_rendering_ready_event.clear()

            header_text = GUIrenderingData.header_text

            connected_data = [row[:] for row in GUIrenderingData.session_connected_table__processed_data]
            connected_colors = [row[:] for row in GUIrenderingData.session_connected_table__compiled_colors]
            connected_num = GUIrenderingData.session_connected_table__num_rows

            disconnected_data = [row[:] for row in GUIrenderingData.session_disconnected_table__processed_data]
            disconnected_colors = [row[:] for row in GUIrenderingData.session_disconnected_table__compiled_colors]
            disconnected_num = GUIrenderingData.session_disconnected_table__num_rows

            connected_rows = list(zip(connected_data, connected_colors, strict=True))
            disconnected_rows = list(zip(disconnected_data, disconnected_colors, strict=True))

            self.update_signal.emit(
                header_text,
                connected_rows,
                disconnected_rows,
                connected_num,
                disconnected_num,
            )


class PersistentMenu(QMenu):
    """Custom QMenu that doesn't close when checkable actions are triggered."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

    def mouseReleaseEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # pylint: disable=invalid-name  # noqa: N802
        """Override mouse release event to prevent auto-closing on checkable actions."""
        if event is None:
            super().mouseReleaseEvent(event)
            return

        action = self.actionAt(event.pos())
        if action and action.isCheckable():
            # Trigger the action but don't close the menu
            action.trigger()
            event.accept()
            return
        # For non-checkable actions, use default behavior (close menu)
        super().mouseReleaseEvent(event)


class MainWindow(QMainWindow):
    def __init__(self, screen_width: int, screen_height: int) -> None:
        super().__init__()

        from modules.guis.utils import resize_window_for_screen

        # Set up the window
        self.setWindowTitle(f'{TITLE}')
        self.setMinimumSize(800, 600)
        resize_window_for_screen(self, screen_width, screen_height)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout for the central widget
        self.main_layout = QVBoxLayout(central_widget)

        # Create the toolbar
        toolbar = QToolBar('Main Toolbar', self)
        toolbar.setAllowedAreas(Qt.ToolBarArea.TopToolBarArea)
        toolbar.setFloatable(False)
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)

        # ----- Open Project Repository Button -----
        open_project_repo_action = QAction('Project Repository', self)
        open_project_repo_action.setToolTip('Open the Session Sniffer GitHub repository in your default web browser')
        open_project_repo_action.triggered.connect(self.open_project_repo)  # pyright: ignore[reportUnknownMemberType]
        toolbar.addAction(open_project_repo_action)  # pyright: ignore[reportUnknownMemberType]

        toolbar.addSeparator()

        # ----- Open Documentation Button -----
        open_documentation_action = QAction('Documentation', self)
        open_documentation_action.setToolTip('View the complete documentation and user guide for Session Sniffer')
        open_documentation_action.triggered.connect(self.open_documentation)  # pyright: ignore[reportUnknownMemberType]
        toolbar.addAction(open_documentation_action)  # pyright: ignore[reportUnknownMemberType]

        toolbar.addSeparator()

        # ----- Join Discord Button -----
        discord_action = QAction('Discord Server', self)
        discord_action.setToolTip('Join the official Session Sniffer Discord community for support and updates')
        discord_action.triggered.connect(self.join_discord)  # pyright: ignore[reportUnknownMemberType]
        toolbar.addAction(discord_action)  # pyright: ignore[reportUnknownMemberType]

        toolbar.addSeparator()

        # ----- Detection Menu -----
        detection_menu_button = QPushButton(' Detection Settings ', self)
        detection_menu_button.setToolTip('Configure notification settings for various player detection scenarios')

        detection_menu = PersistentMenu(self)
        detection_menu.setToolTipsVisible(True)

        # Mobile Detection action
        self.mobile_detection_action = QAction('Mobile (cellular) connection', self)
        self.mobile_detection_action.setToolTip('Get notified when a player joins using a mobile/cellular internet connection')
        self.mobile_detection_action.setCheckable(True)
        self.mobile_detection_action.setChecked(GUIDetectionSettings.mobile_detection_enabled)
        self.mobile_detection_action.triggered.connect(self.toggle_mobile_detection)  # pyright: ignore[reportUnknownMemberType]
        detection_menu.addAction(self.mobile_detection_action)  # pyright: ignore[reportUnknownMemberType]

        # VPN Detection action
        self.vpn_detection_action = QAction('Proxy, VPN or Tor exit address', self)
        self.vpn_detection_action.setToolTip('Get notified when a player joins using a VPN, proxy, or Tor exit node')
        self.vpn_detection_action.setCheckable(True)
        self.vpn_detection_action.setChecked(GUIDetectionSettings.vpn_detection_enabled)
        self.vpn_detection_action.triggered.connect(self.toggle_vpn_detection)  # pyright: ignore[reportUnknownMemberType]
        detection_menu.addAction(self.vpn_detection_action)  # pyright: ignore[reportUnknownMemberType]

        # Hosting Detection action
        self.hosting_detection_action = QAction('Hosting, colocated or data center', self)
        self.hosting_detection_action.setToolTip('Get notified when a player joins from a hosting provider or data center')
        self.hosting_detection_action.setCheckable(True)
        self.hosting_detection_action.setChecked(GUIDetectionSettings.hosting_detection_enabled)
        self.hosting_detection_action.triggered.connect(self.toggle_hosting_detection)  # pyright: ignore[reportUnknownMemberType]
        detection_menu.addAction(self.hosting_detection_action)  # pyright: ignore[reportUnknownMemberType]

        detection_menu.addSeparator()

        # Player Join Notification action
        self.player_join_notification_action = QAction('Player join notifications', self)
        self.player_join_notification_action.setToolTip('Get notified whenever any player joins your session')
        self.player_join_notification_action.setCheckable(True)
        self.player_join_notification_action.setChecked(GUIDetectionSettings.player_join_notifications_enabled)
        self.player_join_notification_action.triggered.connect(self.toggle_player_join_notifications)  # pyright: ignore[reportUnknownMemberType]
        detection_menu.addAction(self.player_join_notification_action)  # pyright: ignore[reportUnknownMemberType]

        # Player Leave Notification action
        self.player_leave_notification_action = QAction('Player leave notifications', self)
        self.player_leave_notification_action.setToolTip('Get notified whenever any player leaves your session')
        self.player_leave_notification_action.setCheckable(True)
        self.player_leave_notification_action.setChecked(GUIDetectionSettings.player_leave_notifications_enabled)
        self.player_leave_notification_action.triggered.connect(self.toggle_player_leave_notifications)  # pyright: ignore[reportUnknownMemberType]
        detection_menu.addAction(self.player_leave_notification_action)  # pyright: ignore[reportUnknownMemberType]

        detection_menu_button.setMenu(detection_menu)
        toolbar.addWidget(detection_menu_button)

        # Header text
        self.header_text = QLabel()
        self.header_text.setTextFormat(Qt.TextFormat.RichText)
        self.header_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.header_text.setWordWrap(True)
        self.header_text.setFont(QFont('Courier', 10, QFont.Weight.Bold))

        # Create container for connected header and controls
        self.connected_header_container = QWidget()
        self.connected_header_container.setStyleSheet(CONNECTED_HEADER_CONTAINER_STYLESHEET)
        self.connected_header_layout = QHBoxLayout(self.connected_header_container)
        self.connected_header_layout.setContentsMargins(0, 0, 0, 0)

        # Custom header for the Session Connected table with matching background as first column
        self.session_connected_header = QLabel('Players connected in your session (0):')
        self.session_connected_header.setTextFormat(Qt.TextFormat.RichText)
        self.session_connected_header.setStyleSheet(CONNECTED_HEADER_TEXT_STYLESHEET)
        self.session_connected_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_connected_header.setFont(QFont('Courier', 9, QFont.Weight.Bold))

        # Add connected header to container with stretch to fill available space
        self.connected_header_layout.addWidget(self.session_connected_header, 1)

        # Add sleek collapse icon button for connected table
        self.connected_collapse_button = QPushButton('▼')
        self.connected_collapse_button.setToolTip('Hide the connected players table')
        self.connected_collapse_button.setStyleSheet(COMMON_COLLAPSE_BUTTON_STYLESHEET)
        self.connected_collapse_button.clicked.connect(self.minimize_connected_section)  # pyright: ignore[reportUnknownMemberType]
        self.connected_header_layout.addWidget(self.connected_collapse_button)

        # Create the table model and view
        while not GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES:  # Wait for the GUI rendering data to be ready
            gui_closed__event.wait(0.1)
        self.connected_table_model = SessionTableModel(GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES)
        self.connected_table_view = SessionTableView(self.connected_table_model, GUIrenderingData.GUI_CONNECTED_PLAYERS_TABLE__FIELD_NAMES.index('Last Rejoin'), Qt.SortOrder.DescendingOrder)
        self.connected_table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Custom)
        self.connected_table_view.setup_static_column_resizing()
        self.connected_table_model.view = self.connected_table_view

        # Add a horizontal line separator
        self.tables_separator = QFrame(self)
        self.tables_separator.setFrameShape(QFrame.Shape.HLine)
        self.tables_separator.setFrameShadow(QFrame.Shadow.Sunken)  # Optional shadow effect

        # Create container for disconnected header and controls
        self.disconnected_header_container = QWidget()
        self.disconnected_header_container.setStyleSheet(DISCONNECTED_HEADER_CONTAINER_STYLESHEET)
        self.disconnected_header_layout = QHBoxLayout(self.disconnected_header_container)
        self.disconnected_header_layout.setContentsMargins(0, 0, 0, 0)

        # Custom header for the Session Disconnected table with matching background as first column
        self.session_disconnected_header = QLabel("Players who've left your session (0):")
        self.session_disconnected_header.setTextFormat(Qt.TextFormat.RichText)
        self.session_disconnected_header.setStyleSheet(DISCONNECTED_HEADER_TEXT_STYLESHEET)
        self.session_disconnected_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_disconnected_header.setFont(QFont('Courier', 9, QFont.Weight.Bold))

        # Add disconnected header to container with stretch to fill available space
        self.disconnected_header_layout.addWidget(self.session_disconnected_header, 1)

        # Add sleek collapse icon button for disconnected table
        self.disconnected_collapse_button = QPushButton('▼')
        self.disconnected_collapse_button.setToolTip('Hide the disconnected players table')
        self.disconnected_collapse_button.setStyleSheet(COMMON_COLLAPSE_BUTTON_STYLESHEET)
        self.disconnected_collapse_button.clicked.connect(self.minimize_disconnected_section)  # pyright: ignore[reportUnknownMemberType]
        self.disconnected_header_layout.addWidget(self.disconnected_collapse_button)

        # Create expand button for when connected section is hidden
        self.connected_expand_button = QPushButton('▲  Show Connected Players (0)')
        self.connected_expand_button.setToolTip('Show the connected players table')
        self.connected_expand_button.setStyleSheet(CONNECTED_EXPAND_BUTTON_STYLESHEET)
        self.connected_expand_button.clicked.connect(self.expand_connected_section)  # pyright: ignore[reportUnknownMemberType]
        self.connected_expand_button.setVisible(False)

        # Create expand button for when disconnected section is hidden
        self.disconnected_expand_button = QPushButton('▲  Show Disconnected Players (0)')
        self.disconnected_expand_button.setToolTip('Show the disconnected players table')
        self.disconnected_expand_button.setStyleSheet(DISCONNECTED_EXPAND_BUTTON_STYLESHEET)
        self.disconnected_expand_button.clicked.connect(self.expand_disconnected_section)  # pyright: ignore[reportUnknownMemberType]
        self.disconnected_expand_button.setVisible(False)

        # Create the table model and view
        while not GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES:  # Wait for the GUI rendering data to be ready
            gui_closed__event.wait(0.1)
        self.disconnected_table_model = SessionTableModel(GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES)
        self.disconnected_table_view = SessionTableView(self.disconnected_table_model, GUIrenderingData.GUI_DISCONNECTED_PLAYERS_TABLE__FIELD_NAMES.index('Last Seen'), Qt.SortOrder.AscendingOrder)
        self.disconnected_table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Custom)
        self.disconnected_table_view.setup_static_column_resizing()
        self.disconnected_table_model.view = self.disconnected_table_view

        # Layout to organize the widgets
        self.main_layout.addWidget(self.header_text)
        self.main_layout.addWidget(self.connected_header_container)
        self.main_layout.addWidget(self.connected_table_view)
        self.main_layout.addWidget(self.tables_separator)
        self.main_layout.addWidget(self.disconnected_header_container)
        self.main_layout.addWidget(self.disconnected_table_view)
        self.main_layout.addWidget(self.connected_expand_button)
        self.main_layout.addWidget(self.disconnected_expand_button)

        # Initialize tracking variables for text updates optimization
        self._last_connected_count = -1
        self._last_disconnected_count = -1

        # Initialize tracking variables for selection counts
        self._connected_selected_count = 0
        self._disconnected_selected_count = 0

        # Connect to selection change signals to track selected cells
        self.connected_table_view.selectionModel().selectionChanged.connect(  # pyright: ignore[reportUnknownMemberType]
            lambda: self._update_selection_count(self.connected_table_view, 'connected'),
        )
        self.disconnected_table_view.selectionModel().selectionChanged.connect(  # pyright: ignore[reportUnknownMemberType]
            lambda: self._update_selection_count(self.disconnected_table_view, 'disconnected'),
        )

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Create the worker thread for table updates
        self.worker_thread = GUIWorkerThread(
            self.connected_table_view,
            self.disconnected_table_view,
        )
        self.worker_thread.update_signal.connect(self.update_gui)  # pyright: ignore[reportUnknownMemberType]
        self.worker_thread.start()

    def closeEvent(self, event: QCloseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # pylint: disable=invalid-name  # noqa: N802
        gui_closed__event.set()  # Signal the thread to stop
        self.worker_thread.quit()  # Stop the QThread
        self.worker_thread.wait()  # Wait for the thread to finish

        if event is not None:
            event.accept()

        terminate_script('EXIT')

    # --------------------------------------------------------------------------
    # Custom / internal management methods
    # --------------------------------------------------------------------------

    def _update_connected_header_with_selection(self) -> None:
        """Update the connected table header to include selection information."""
        base_text = f'Players connected in your session ({self._last_connected_count}):'
        if self._connected_selected_count > 0:
            player_text = 'player' if self._connected_selected_count == 1 else 'players'
            combined_text = f'{base_text} ({self._connected_selected_count} {player_text} selected)'
        else:
            combined_text = base_text

        self.session_connected_header.setText(combined_text)

    def _update_disconnected_header_with_selection(self) -> None:
        """Update the disconnected table header to include selection information."""
        base_text = f"Players who've left your session ({self._last_disconnected_count}):"
        if self._disconnected_selected_count > 0:
            player_text = 'player' if self._disconnected_selected_count == 1 else 'players'
            combined_text = f'{base_text} ({self._disconnected_selected_count} {player_text} selected)'
        else:
            combined_text = base_text

        self.session_disconnected_header.setText(combined_text)

    def _update_selection_count(self, table_view: SessionTableView, table_type: str) -> None:
        """Update the selection count for the specified table and refresh table headers."""
        selection_model = table_view.selectionModel()
        selected_indexes = selection_model.selectedIndexes()

        # Count unique rows (players) instead of individual cells
        unique_rows = {index.row() for index in selected_indexes}
        selected_count = len(unique_rows)

        if table_type == 'connected':
            self._connected_selected_count = selected_count
            self._update_connected_header_with_selection()
        elif table_type == 'disconnected':
            self._disconnected_selected_count = selected_count
            self._update_disconnected_header_with_selection()

    def _update_separator_visibility(self) -> None:
        """Update the separator visibility based on whether both tables are visible."""
        both_tables_visible = (
            self.connected_table_view.isVisible()
            and self.disconnected_table_view.isVisible()
        )
        self.tables_separator.setVisible(both_tables_visible)

    def expand_connected_section(self) -> None:
        """Handle the expand button click to show the connected section."""
        self.connected_expand_button.setVisible(False)
        self.connected_header_container.setVisible(True)
        self.connected_table_view.setVisible(True)
        self._update_separator_visibility()
        self.connected_collapse_button.setVisible(True)

        self.connected_table_model.refresh_view()  # Refresh the table view to ensure it's up to date after being hidden

    def expand_disconnected_section(self) -> None:
        """Handle the expand button click to show the disconnected section."""
        self.disconnected_expand_button.setVisible(False)
        self.disconnected_header_container.setVisible(True)
        self.disconnected_table_view.setVisible(True)
        self._update_separator_visibility()
        self.disconnected_collapse_button.setVisible(True)

        self.disconnected_table_model.refresh_view()  # Refresh the table view to ensure it's up to date after being hidden

    def minimize_connected_section(self) -> None:
        """Minimize the connected table completely."""
        self.connected_collapse_button.setVisible(False)
        self.connected_header_container.setVisible(False)
        self.connected_table_view.setVisible(False)
        self.tables_separator.setVisible(False)
        self.connected_expand_button.setText(f'▲  Show Connected Players ({self.connected_table_model.rowCount()})')  # Set initial count on the expand button
        self.connected_expand_button.setVisible(True)

    def minimize_disconnected_section(self) -> None:
        """Minimize the disconnected table completely."""
        self.disconnected_collapse_button.setVisible(False)
        self.disconnected_header_container.setVisible(False)
        self.disconnected_table_view.setVisible(False)
        self.tables_separator.setVisible(False)
        self.disconnected_expand_button.setText(f'▲  Show Disconnected Players ({self.disconnected_table_model.rowCount()})')  # Set initial count on the expand button
        self.disconnected_expand_button.setVisible(True)

    def update_gui(
        self,
        header_text: str,
        connected_rows: list[tuple[list[str], list[CellColor]]],
        disconnected_rows: list[tuple[list[str], list[CellColor]]],
        connected_num: int,
        disconnected_num: int,
    ):
        """Update header text and table data for connected and disconnected players."""
        # Update the main header text
        self.header_text.setText(header_text)

        # Check if counts changed to optimize text updates
        connected_count_changed = self._last_connected_count != connected_num
        disconnected_count_changed = self._last_disconnected_count != disconnected_num

        if connected_count_changed:
            self._last_connected_count = connected_num
            self._update_connected_header_with_selection()

        # Process connected players data
        for processed_data, compiled_colors in connected_rows:
            ip = self.connected_table_model.get_ip_from_data_safely(processed_data)

            # Remove from disconnected table (maintain data consistency)
            disconnected_row_index = self.disconnected_table_model.get_row_index_by_ip(ip)
            if disconnected_row_index is not None:
                self.disconnected_table_model.delete_row(disconnected_row_index)

            # Update connected table data
            connected_row_index = self.connected_table_model.get_row_index_by_ip(ip)
            if connected_row_index is None:
                self.connected_table_model.add_row_without_refresh(processed_data, compiled_colors)
            else:
                self.connected_table_model.update_row_without_refresh(connected_row_index, processed_data, compiled_colors)

        # Only perform expensive UI operations if tables are visible
        if self.connected_table_view.isVisible():
            self.connected_table_model.sort_current_column()
            self.connected_table_view.adjust_username_column_width()
        elif connected_count_changed:
            self.connected_expand_button.setText(f'▲  Show Connected Players ({connected_num})')

        if disconnected_count_changed:
            self._last_disconnected_count = disconnected_num
            self._update_disconnected_header_with_selection()

        # Process disconnected players data
        for processed_data, compiled_colors in disconnected_rows:
            ip = self.disconnected_table_model.get_ip_from_data_safely(processed_data)

            # Remove from connected table (maintain data consistency)
            connected_row_index = self.connected_table_model.get_row_index_by_ip(ip)
            if connected_row_index is not None:
                self.connected_table_model.delete_row(connected_row_index)

            # Update disconnected table data
            disconnected_row_index = self.disconnected_table_model.get_row_index_by_ip(ip)
            if disconnected_row_index is None:
                self.disconnected_table_model.add_row_without_refresh(processed_data, compiled_colors)
            else:
                self.disconnected_table_model.update_row_without_refresh(disconnected_row_index, processed_data, compiled_colors)

        # Only perform expensive UI operations if tables are visible
        if self.disconnected_table_view.isVisible():
            self.disconnected_table_model.sort_current_column()
            self.disconnected_table_view.adjust_username_column_width()
        elif disconnected_count_changed:
            self.disconnected_expand_button.setText(f'▲  Show Disconnected Players ({disconnected_num})')

    def open_project_repo(self) -> None:
        from modules.constants.standalone import GITHUB_REPO_URL

        webbrowser.open(GITHUB_REPO_URL)

    def open_documentation(self) -> None:
        from modules.constants.standalone import DOCUMENTATION_URL

        webbrowser.open(DOCUMENTATION_URL)

    def join_discord(self) -> None:
        from modules.constants.standalone import DISCORD_INVITE_URL

        webbrowser.open(DISCORD_INVITE_URL)

    def toggle_mobile_detection(self) -> None:
        """Toggle Mobile detection on/off and save the setting."""
        GUIDetectionSettings.mobile_detection_enabled = self.mobile_detection_action.isChecked()

        # Clear the Mobile notifications set when disabling to allow re-detection
        if not GUIDetectionSettings.mobile_detection_enabled:
            MobileWarnings.clear_all_notified_ips()

    def toggle_vpn_detection(self) -> None:
        """Toggle VPN detection on/off and save the setting."""
        GUIDetectionSettings.vpn_detection_enabled = self.vpn_detection_action.isChecked()

        # Clear the VPN notifications set when disabling to allow re-detection
        if not GUIDetectionSettings.vpn_detection_enabled:
            VPNWarnings.clear_all_notified_ips()

    def toggle_hosting_detection(self) -> None:
        """Toggle Hosting detection on/off and save the setting."""
        GUIDetectionSettings.hosting_detection_enabled = self.hosting_detection_action.isChecked()

        # Clear the Hosting notifications set when disabling to allow re-detection
        if not GUIDetectionSettings.hosting_detection_enabled:
            HostingWarnings.clear_all_notified_ips()

    def toggle_player_join_notifications(self) -> None:
        """Toggle player join notifications on/off."""
        GUIDetectionSettings.player_join_notifications_enabled = self.player_join_notification_action.isChecked()

    def toggle_player_leave_notifications(self) -> None:
        """Toggle player leave notifications on/off."""
        GUIDetectionSettings.player_leave_notifications_enabled = self.player_leave_notification_action.isChecked()


class ClickableLabel(QLabel):
    clicked = pyqtSignal()

    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # pylint: disable=invalid-name  # noqa: N802
        if event is not None and event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()


class DiscordIntro(QDialog):
    def __init__(self) -> None:
        super().__init__()

        # Ensure the dialog is modal, blocking interaction with the main window
        self.setModal(True)

        WINDOW_TITLE = '🏆 Join our Discord Community! 🤝'  # pylint: disable=invalid-name

        # Set up the window
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(460, 160)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool | Qt.WindowType.Dialog)  # | Qt.WindowType.WindowStaysOnTopHint

        # Set window opacity to 0 for fade-in animation
        self.setWindowOpacity(0)

        # Styling for the main container window
        self.setStyleSheet(DISCORD_POPUP_MAIN_STYLESHEET)

        self.fade_out = QPropertyAnimation(self, b'windowOpacity')

        # Exit button in the top right corner
        self.exit_button = QPushButton('x', self)
        self.exit_button.setFixedSize(16, 16)  # Make the width and height equal
        self.exit_button.setToolTip('Close this popup')
        self.exit_button.setStyleSheet(DISCORD_POPUP_EXIT_BUTTON_STYLESHEET)
        self.exit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.exit_button.clicked.connect(self.close_popup)  # pyright: ignore[reportUnknownMemberType]

        # Layout for the window content
        layout = QVBoxLayout()

        # Add the exit button to the top right
        exit_layout = QHBoxLayout()
        exit_layout.addStretch(1)  # Spacer
        exit_layout.addWidget(self.exit_button)
        layout.addLayout(exit_layout)

        # Label for the Discord message
        self.title_label = QLabel(
            f"<font size='6' color='#5865F2'><b>{WINDOW_TITLE}</b></font>",
            self)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self.title_label)

        layout.addItem(QSpacerItem(0, 4, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))  # Spacer

        # Join button container
        self.join_button = QPushButton('🔥 Join Now - Session Sniffer Discord! 🔥', self)
        self.join_button.setToolTip('Open Discord and join the Session Sniffer community server')
        self.join_button.setStyleSheet(DISCORD_POPUP_JOIN_BUTTON_STYLESHEET)
        self.join_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.join_button.clicked.connect(self.open_discord)  # pyright: ignore[reportUnknownMemberType]

        # Set button width to 75% of the window width
        self.join_button.setMaximumWidth(int(self.width() * 0.75))

        # Center the button horizontally using a layout
        button_layout = QHBoxLayout()
        button_layout.addStretch(1)  # Spacer before the button
        button_layout.addWidget(self.join_button)
        button_layout.addStretch(1)  # Spacer after the button

        layout.addLayout(button_layout)  # Add the button layout to the main layout

        # Clickable text "Don't remind me again"
        self.dont_remind_me_label = ClickableLabel("<font size='3' color='#B0B0B0'><u>Don't remind me again</u></font>", self)
        self.dont_remind_me_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.dont_remind_me_label.setToolTip('Disable Discord popup notifications permanently')
        self.dont_remind_me_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.dont_remind_me_label.clicked.connect(self.dont_remind_me)  # pyright: ignore[reportUnknownMemberType]

        layout.addItem(QSpacerItem(0, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))  # Spacer
        layout.addWidget(self.dont_remind_me_label)

        # Apply margin here to adjust widget spacing
        layout.setContentsMargins(10, 10, 10, 10)  # Add margin to the layout

        # Set the main layout of the window
        self.setLayout(layout)

        # Show the window to allow size calculations
        self.show()

        # After the window is shown, center it
        self.center_window()

        # Fade-in animation
        self.fade_in = QPropertyAnimation(self, b'windowOpacity')
        self.fade_in.setDuration(1000)
        self.fade_in.setStartValue(0)
        self.fade_in.setEndValue(1)
        self.fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.fade_in.start()

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Initialize variables to track mouse position
        self._drag_pos: QPoint | None = None

    # pylint: disable=invalid-name
    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # noqa: N802
        if (
            event is not None
            and event.button() == Qt.MouseButton.LeftButton
            and not self.exit_button.underMouse() and not self.join_button.underMouse() and not self.dont_remind_me_label.underMouse()  # Only allow dragging if the click is not on a button
        ):
            self._drag_pos = event.globalPosition().toPoint()

        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # noqa: N802
        if (
            event is not None
            and self._drag_pos is not None  # If mouse is pressed, move the window
        ):
            delta = event.globalPosition().toPoint() - self._drag_pos
            self.move(self.pos() + delta)
            self._drag_pos = event.globalPosition().toPoint()

        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # noqa: N802
        self._drag_pos = None  # Reset drag position when mouse is released

        super().mouseReleaseEvent(event)
    # pylint: enable=invalid-name

    def center_window(self) -> None:
        screen = app.primaryScreen()
        if screen is None:
            raise PrimaryScreenNotFoundError

        screen_geometry = screen.geometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)

    def open_discord(self) -> None:
        from modules.constants.standalone import DISCORD_INVITE_URL

        webbrowser.open(DISCORD_INVITE_URL)

        Settings.SHOW_DISCORD_POPUP = False
        Settings.reconstruct_settings()

        self.close_popup()

    def dont_remind_me(self) -> None:
        Settings.SHOW_DISCORD_POPUP = False
        Settings.reconstruct_settings()

        self.close_popup()

    def close_popup(self) -> None:
        # Smooth fade-out before closing
        self.fade_out.setDuration(500)
        self.fade_out.setStartValue(1)  # Start from fully opaque
        self.fade_out.setEndValue(0)    # Fade to fully transparent
        self.fade_out.setEasingCurve(QEasingCurve.Type.InCubic)
        self.fade_out.finished.connect(self.close)  # pyright: ignore[reportUnknownMemberType]  # Close the window after the fade-out finishes
        self.fade_out.start()


if __name__ == '__main__':
    # Initialize the main application
    window = MainWindow(screen_width, screen_height)
    window.show()

    if Settings.SHOW_DISCORD_POPUP:
        # Delay the popup opening by 3 seconds
        QTimer.singleShot(3000, lambda: DiscordIntro().exec())  # pyright: ignore[reportUnknownMemberType]

    # Start the application's event loop
    sys.exit(app.exec())
