"""Utility functions for GUI-related operations.

This module provides helper functions to interact with GUI elements.
"""

from PyQt6.QtWidgets import QDialog, QMainWindow

from .app import app
from .exceptions import PrimaryScreenNotFoundError


def get_screen_size():
    screen = app.primaryScreen()
    if screen is None:
        raise PrimaryScreenNotFoundError

    size = screen.size()
    return size.width(), size.height()


def resize_window_for_screen(window: QMainWindow | QDialog, screen_width: int, screen_height: int):
    """Resize a window based on the screen resolution.

    Args:
        window (QWidget): The window to resize.
        screen_width (int): The width of the screen.
        screen_height (int): The height of the screen.
    """
    if (screen_width, screen_height) >= (2560, 1440):
        window.resize(1400, 900)
    elif (screen_width, screen_height) >= (1920, 1080):
        window.resize(1200, 720)
    elif (screen_width, screen_height) >= (1024, 768):
        window.resize(940, 680)
