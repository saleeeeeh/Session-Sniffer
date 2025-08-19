"""GUI Stylesheets Module.

This module contains all the QSS (Qt Style Sheets) used throughout the application.
Centralizing stylesheets here makes them easier to maintain and modify.
"""

# =============================================================================
# HEADER STYLES
# =============================================================================

SESSION_CONNECTED_HEADER_STYLESHEET = "background-color: green; color: white; font-size: 16px; font-weight: bold; padding: 5px;"

SESSION_DISCONNECTED_HEADER_STYLESHEET = "background-color: red; color: white; font-size: 16px; font-weight: bold; padding: 5px;"


# =============================================================================
# DISCORD DIALOG STYLES
# =============================================================================

DISCORD_POPUP_MAIN_STYLESHEET = """
background-color: #222244;  /* Dark blueish background */
border-radius: 15px;        /* Rounded corners */
color: white;
""".strip()

DISCORD_POPUP_EXIT_BUTTON_STYLESHEET = """
font-size: 10px;
color: white;
background-color: #FF4C4C;  /* Light red background */
border-radius: 15px;        /* Make it circular */
""".strip()

DISCORD_POPUP_JOIN_BUTTON_STYLESHEET = """
font-size: 14px;
padding: 7px;
background-color: #5865F2;  /* Discord blue */
color: white;
border-radius: 10px;
border: none;
""".strip()
