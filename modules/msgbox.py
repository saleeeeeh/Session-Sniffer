"""
This module provides a wrapper for the Windows MessageBox API using ctypes.

It defines two main components:
- MsgBox.ReturnValues: Enum class representing the possible return values from a MessageBox.
- MsgBox.Style: IntFlag class representing the different styles and options available for the MessageBox.

The MsgBox.show() method can be used to display a message box with custom buttons, and behavior.
"""
import enum
import ctypes


class MsgBox:
    """
    A class to interact with the Windows MessageBox API.

    Provides functionality to display a message box with various button options, and behaviors.
    """

    # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#return-value
    class ReturnValues(enum.IntEnum):
        ID_ABORT = 3       # The Abort button was selected.
        ID_CANCEL = 2      # The Cancel button was selected.
        ID_CONTINUE = 11   # The Continue button was selected.
        ID_IGNORE = 5      # The Ignore button was selected.
        ID_NO = 7          # The No button was selected.
        ID_OK = 1          # The OK button was selected.
        ID_RETRY = 4       # The Retry button was selected.
        ID_TRY_AGAIN = 10  # The Try Again button was selected.
        ID_YES = 6         # The Yes button was selected.

    class Style(enum.IntFlag):
        # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw
        # https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/msgbox-function
        # pylint: disable=implicit-flag-alias
        OK_ONLY = 0                     # Display OK button only.
        OK_CANCEL = 1                   # Display OK and Cancel buttons.
        ABORT_RETRY_IGNORE = 2          # Display Abort, Retry, and Ignore buttons.
        YES_NO_CANCEL = 3               # Display Yes, No, and Cancel buttons.
        YES_NO = 4                      # Display Yes and No buttons.
        RETRY_CANCEL = 5                # Display Retry and Cancel buttons.
        CRITICAL = 16                   # Display Critical Message icon.
        QUESTION = 32                   # Display Warning Query icon.
        EXCLAMATION = 48                # Display Warning Message icon.
        INFORMATION = 64                # Display Information Message icon.
        DEFAULT_BUTTON1 = 0             # First button is default.
        DEFAULT_BUTTON2 = 256           # Second button is default.
        DEFAULT_BUTTON3 = 512           # Third button is default.
        DEFAULT_BUTTON4 = 768           # Fourth button is default.
        APPLICATION_MODAL = 0           # Application modal; the user must respond to the message box before continuing work.
        SYSTEM_MODAL = 4096             # System modal; all applications are suspended until the user responds.
        MSG_BOX_HELP_BUTTON = 16384     # Adds Help button to the message box.
        MSG_BOX_SET_FOREGROUND = 65536  # Specifies the message box window as the foreground window.
        MSG_BOX_RIGHT = 524288          # Text is right-aligned.
        MSG_BOX_RTL_READING = 1048576   # Specifies text should appear as right-to-left on Hebrew and Arabic systems.
        # pylint: enable=implicit-flag-alias

    @staticmethod
    def show(title: str, message: str, style: Style):
        msgbox_result = ctypes.windll.user32.MessageBoxW(0, message, title, style)
        if not isinstance(msgbox_result, int):
            raise TypeError(f'Expected "int" object, got "{type(msgbox_result).__name__}"')
        return msgbox_result

# TODO:
# This will be useful for UserIPDatabases._notify_conflict(), once a conflic is resolved, automatically close it's msgbox.
#@classmethod
#def close_after_condition(cls, title: str, message: str, style: Style, condition_func: Callable):
#    """
#    Displays a message box and automatically closes it when the provided condition function returns True.
#
#    Args:
#        title (str): The title of the message box.
#        message (str): The message to display in the message box.
#        style (Style): The style for the message box.
#        condition_func (Callable): A function that returns a boolean. The message box will close when this function returns True.
#    """
#    msg_thread = threading.Thread(target=cls.show, args=(title, message, style))
#    msg_thread.start()
#
#    while not condition_func():
#        time.sleep(0.1)
#
#    ctypes.windll.user32.PostMessageW(0, 0x0010, 0, 0)  # Close the message box
#
#    msg_thread.join()
