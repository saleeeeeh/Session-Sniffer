"""Utility Module.

This module contains a variety of helper functions and custom exceptions used across the project.
"""

# Standard Python Libraries
import contextlib
from pathlib import Path
from typing import Literal, Any

# External/Third-party Python Libraries
from packaging.version import Version


class InvalidFileError(Exception):
    """Custom exception to raise when a file is not valid."""


class InvalidBooleanValueError(Exception):
    pass


class InvalidNoneTypeValueError(Exception):
    pass


class NoMatchFoundError(Exception):
    """Custom exception raised when no case-insensitive match is found."""
    def __init__(self, input_value: str, message: str = "No matching value found in the provided list"):
        self.input_value = input_value
        self.message = f"{message}: '{input_value}'"
        super().__init__(self.message)


def is_pyinstaller_compiled():
    import sys

    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")  # https://pyinstaller.org/en/stable/runtime-information.html


def set_window_title(title: str):
    print(f"\033]0;{title}\007", end="")


def clear_screen():
    print("\033c", end="")


def pluralize(variable: int):
    return "s" if variable > 1 else ""


def validate_file(file_path: Path):
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path.absolute()}")
    if not file_path.is_file():
        raise InvalidFileError(f"Invalid file: {file_path.absolute()}")


def format_project_version(version: Version):
    from datetime import datetime, UTC as DT_UTC

    if version.local:
        date_time = datetime.strptime(version.local, "%Y%m%d.%H%M").replace(tzinfo=DT_UTC).strftime("%Y/%m/%d (%H:%M)")

    return f"v{version.public} - {date_time}" if version.local else f"v{version.public}"


def get_documents_folder(*, use_alternative_method: bool = False):
    """Retrieve the Path object to the current user's "Documents" folder by querying the Windows registry.

    Args:
        use_alternative_method: If set to `True`, the alternative method will be used to retrieve the "Documents" folder.
        If set to `False` (default), the registry-based method will be used.

    Returns:
        Path: A `Path` object pointing to the user's "Documents" folder.

    Raises:
        TypeError: If the retrieved path is not a string.
    """
    if use_alternative_method:
        # Alternative method using SHGetKnownFolderPath from WinAPI
        from win32com.shell import shell, shellcon  # pylint: disable=import-error,no-name-in-module  # type: ignore[import-error]  # Seems like we can also use `win32comext.shell`

        # Get the Documents folder path
        documents_path = shell.SHGetKnownFolderPath(shellcon.FOLDERID_Documents, 0)
    else:
        # Default method using Windows registry
        import winreg
        from modules.constants.standalone import USER_SHELL_FOLDERS__REG_KEY

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, USER_SHELL_FOLDERS__REG_KEY) as key:
            documents_path, _ = winreg.QueryValueEx(key, "Personal")

    if not isinstance(documents_path, str):
        raise TypeError(f'Expected "str", got "{type(documents_path).__name__}"')

    return Path(documents_path)


def resource_path(relative_path: Path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    import sys

    base_path = getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)  # .parent twice because of modularizing bruh
    if not isinstance(base_path, Path):
        base_path = Path(base_path)
    return base_path / relative_path


def take(n: int, input_list: list[Any]):
    """Return first n items from the given input list."""
    return input_list[:n]


def concat_lists_no_duplicates(*lists: list[Any]):
    """Concatenate multiple lists while removing duplicates and preserving order.

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


def get_pid_by_path(filepath: Path):
    import psutil

    for process in psutil.process_iter(["pid", "exe"]):
        if process.info["exe"] == str(filepath.absolute()):
            return process.pid
    return None


def is_file_need_newline_ending(file: Path):
    if file.stat().st_size == 0:
        return False

    return not file.read_bytes().endswith(b"\n")


def write_lines_to_file(file: Path, mode: Literal["w", "x", "a"], lines: list[str]):
    """Writes or appends a list of lines to a file, ensuring proper newline handling.

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


def terminate_process_tree(pid: int | None = None):
    """Terminates the process with the given PID and all its child processes.

    Defaults to the current process if no PID is specified.
    """
    import psutil

    pid = pid or psutil.Process().pid

    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                child.terminate()
        psutil.wait_procs(children, timeout=5)
        with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            parent.terminate()
        parent.wait(5)
    except psutil.NoSuchProcess:
        pass


def check_case_insensitive_and_exact_match(input_value: str, custom_values_list: list[str]):
    """Check if the input value matches any string in the list case-insensitively, and whether it also matches exactly (case-sensitive).

    It also returns the correctly capitalized version of the matched value from the list if a case-insensitive match is found.
    If no match is found, raises a NoMatchFoundError.

    Returns a tuple of three values:
    - The first boolean is True if the exact case-sensitive match is found.
    - The second value is the correctly capitalized version of the matched string, never None.
    """
    case_sensitive_match = False
    normalized_match = None

    lowered_input_value = input_value.lower()
    for value in custom_values_list:
        if value.lower() == lowered_input_value:
            normalized_match = value
            if normalized_match == input_value:
                case_sensitive_match = True

            return case_sensitive_match, normalized_match

    raise NoMatchFoundError(input_value)


def custom_str_to_bool(string: str, only_match_against: bool | None = None):
    """Return the boolean value represented by the string, regardless of case.

    Raise an "InvalidBooleanValueError" if the string does not match a boolean value.

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

    if string != str(resolved_value):
        need_rewrite_current_setting = True

    return resolved_value, need_rewrite_current_setting


def custom_str_to_nonetype(string: str):
    """Return the NoneType value represented by the string for lowercase or any case variation; otherwise, it raises an "InvalidNoneTypeValueError".

    Args:
        string: The NoneType string to be checked.
    """
    if not string.lower() == "none":
        raise InvalidNoneTypeValueError("Input is not a valid NoneType value")

    is_string_literal_none = string == "None"
    return None, is_string_literal_none
