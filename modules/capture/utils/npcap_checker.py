"""NPCap Checker Module.

This module provides a utility function to check whether NPCap is installed on the system.
NPCap is required for network packet capturing in Windows environments.
"""

# Standard Python Libraries
import subprocess

# Local Python Libraries (Included with Project)
from modules.constants.standard import SC_EXE


def is_npcap_installed():
    try:
        subprocess.run([SC_EXE, "query", "npcap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        return False
    return True
