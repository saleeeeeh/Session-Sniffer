"""
NPCap Checker Module

This module provides a utility function to check whether NPCap is installed on the system.
NPCap is required for network packet capturing in Windows environments.
"""

# Standard Python Libraries
import subprocess


def is_npcap_installed():
    try:
        subprocess.run(["sc", "query", "npcap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        return False
    return True
