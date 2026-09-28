"""Stylesheets for the main application dashboard header."""

MAIN_HEADER_CONTAINER_STYLESHEET = 'QFrame#mainHeader { background-color: transparent; border: none; }'

HEADER_TITLE_STYLESHEET = 'font-size: 13pt; font-weight: 700; color: #ffffff;'

HEADER_VERSION_BADGE_STYLESHEET = 'color: #8a9bb0; font-size: 8.5pt; font-weight: normal; margin-left: 2px;'

HEADER_SUBTITLE_STYLESHEET = 'font-size: 8.5pt; color: #8a9bb0;'

HEADER_STOPPED_BADGE_STYLESHEET = """
color: #ff5252;
background-color: rgba(255, 82, 82, 0.16);
border: 1px solid rgba(255, 82, 82, 0.45);
border-radius: 4px;
padding: 1px 7px;
font-size: 8pt;
font-weight: 700;
letter-spacing: 0.5px;
""".strip()

HEADER_SEARCH_BAR_STYLESHEET = """
QLineEdit#headerSearchBar {
    min-height: 28px;
    max-height: 30px;
    padding: 0 8px 0 6px;
    color: #ffffff;
    background-color: rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 6px;
    font-size: 9pt;
}
QLineEdit#headerSearchBar:focus {
    border: 1px solid #48b774;
    background-color: rgba(0, 0, 0, 0.5);
}
""".strip()

HEADER_SEARCH_COMBO_STYLESHEET = """
QComboBox#headerSearchCombo {
    min-height: 28px;
    max-height: 30px;
    padding: 0 22px 0 8px;
    color: #e0e0e0;
    background-color: rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 6px;
    font-size: 9pt;
}
QComboBox#headerSearchCombo:hover,
QComboBox#headerSearchCombo:focus,
QComboBox#headerSearchCombo:on {
    border: 1px solid #48b774;
}
QComboBox#headerSearchCombo::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: none;
}
QComboBox#headerSearchCombo QAbstractItemView {
    background-color: #2b2b2b;
    color: #e0e0e0;
    border: 1px solid #3a3a3a;
    border-radius: 4px;
    padding: 4px 2px;
    outline: none;
}
QComboBox#headerSearchCombo QAbstractItemView::item {
    min-height: 22px;
    padding: 2px 8px;
    margin: 1px 2px;
    border-radius: 3px;
    border: none;
    background-color: transparent;
    color: #e0e0e0;
}
QComboBox#headerSearchCombo QAbstractItemView::item:hover {
    background-color: #3a3a3a;
    color: #ffffff;
}
QComboBox#headerSearchCombo QAbstractItemView::item:selected {
    background-color: #3a3a3a;
    color: #ffffff;
}
QComboBox#headerSearchCombo QAbstractItemView::item:selected:hover {
    background-color: #444444;
    color: #ffffff;
}
QComboBox#headerSearchCombo QAbstractItemView::item:focus {
    background-color: #3a3a3a;
    color: #ffffff;
    outline: none;
}
""".strip()

HEADER_STAT_CARD_STYLESHEET = """
QFrame#headerStatsContainer {
    background-color: rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 6px;
}
""".strip()

STAT_CARD_TITLE_STYLESHEET = 'font-size: 8pt; font-weight: 500; color: #8a9bb0;'

STAT_CARD_UPTIME_VALUE_STYLESHEET = "font-size: 10.5pt; font-weight: 700; color: #00e676; font-family: 'Consolas', 'Courier New', monospace;"

STAT_CARD_PACKETS_VALUE_STYLESHEET = "font-size: 10.5pt; font-weight: 700; color: #00e676; font-family: 'Consolas', 'Courier New', monospace;"

HEADER_STATS_DIVIDER_STYLESHEET = 'background-color: rgba(255, 255, 255, 0.14); border: none; max-width: 1px; min-width: 1px; margin: 4px 6px;'
