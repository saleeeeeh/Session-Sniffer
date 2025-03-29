"""
Module for defining and managing constants that require a local function to be executed first.
"""

# Standard Python Libraries
from pathlib import Path

# Local Python Libraries (Included with Project)
from modules.utils import get_documents_folder, resource_path


CHERAX__PLUGIN__LOG_PATH = get_documents_folder() / "Cherax/Lua/GTA_V_Session_Sniffer-plugin/log.txt"
BIN_PATH = resource_path(Path("bin/"))
SCRIPTS_PATH = resource_path(Path("scripts/"))
SETUP_PATH = resource_path(Path("setup/"))
TTS_PATH = resource_path(Path("TTS/"))
