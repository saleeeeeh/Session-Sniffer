"""Module for defining constants that require imports from third-party libraries."""


# External/Third-party Python Libraries
from qdarkstyle.colorsystem import Gray
from PyQt6.QtGui import QColor  # pylint: disable=no-name-in-module
from tzlocal import get_localzone

LOCAL_TZ = get_localzone()

# GUI-related constant
HARDCODED_DEFAULT_TABLE_BACKGROUND_CELL_COLOR = QColor(Gray.B10)
