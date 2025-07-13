"""NPCap Checker Module.

This module provides a utility function to check whether NPCap is installed on the system.
NPCap is required for network packet capturing in Windows environments.
"""
import subprocess
import webbrowser
from contextlib import suppress

from modules.constants.local import NPCAP_SETUP_PATH
from modules.constants.standalone import TITLE
from modules.constants.standard import SC_EXE
from modules.msgbox import MsgBox
from modules.utils import format_triple_quoted_text

NPCAP_SERVICE_QUERY_CMD = (SC_EXE, "query", "npcap")
NPCAP_INSTALLER_CMD = (NPCAP_SETUP_PATH,)


def is_npcap_installed():
    """Check if the Npcap driver is installed on the system."""
    with suppress(subprocess.CalledProcessError):
        subprocess.run(NPCAP_SERVICE_QUERY_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    return False


def run_npcap_installer():
    """Attempt to run the Npcap installer."""
    with suppress(subprocess.CalledProcessError):
        subprocess.run(NPCAP_INSTALLER_CMD, shell=True, check=True)
        return True
    return False


def open_npcap_installer_in_browser():
    """Open the Npcap installer in the web browser for manual installation."""
    webbrowser.open("https://nmap.org/npcap/")


def ensure_npcap_installed():
    """Ensure that the Npcap driver is installed. If not, try to run the installer as admin or open it in a browser."""
    if is_npcap_installed():
        return

    MsgBox.show(
        title=TITLE,
        text=format_triple_quoted_text("""
            ERROR:
                Could not detect "Npcap" driver installed on your system.

            Opening the "Npcap" setup installer for you.
        """),
        style=MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND,
    )

    run_npcap_installer()

    while not is_npcap_installed():
        open_npcap_installer_in_browser()

        MsgBox.show(
            title=TITLE,
            text=format_triple_quoted_text("""
                ERROR:
                    Failed to run the Npcap installer as admin.

                The Npcap installer has been opened in your web browser.
                Please ensure you have administrator privileges and run the installer manually.
            """),
            style=MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONEXCLAMATION | MsgBox.Style.MB_SETFOREGROUND,
        )
