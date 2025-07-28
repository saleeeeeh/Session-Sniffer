"""GUI-related custom exceptions.

This module contains custom exception classes for GUI operations.
"""


class PrimaryScreenNotFoundError(Exception):
    """Raised when no primary screen is detected in GUI operations."""

    def __init__(self):
        super().__init__("No primary screen detected")


class UnsupportedSortColumnError(Exception):
    """Raised when an unsupported column name is used for sorting."""

    def __init__(self, column_name: str):
        super().__init__(f"Sorting by column '{column_name}' is not supported.")


class TableDataConsistencyError(Exception):
    """Raised when table data and color arrays are in an inconsistent state."""

    def __init__(self, *, case: str):
        error_messages = {
            "colors_without_data": "Inconsistent state: It's not possible to have colors if there's no data.",
            "data_without_colors": "Inconsistent state: It's not possible to have data without colors.",
            "empty_combined": "Inconsistent state: 'combined' is unexpectedly empty at this point.",
        }

        super().__init__(error_messages[case])


class InvalidDateFieldConfigurationError(Exception):
    """Raised when GUI date field settings are invalid (both date and time disabled)."""

    def __init__(self):
        super().__init__("Invalid settings: Both date and time are disabled.")
