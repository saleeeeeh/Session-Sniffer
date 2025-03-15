# Standard Python Libraries
from typing import Union, Literal
from typing import NamedTuple

# External/Third-party Python Libraries
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QLabel,
    QHeaderView,
    QPushButton,
    QHBoxLayout
)


class InterfaceSelectionData(NamedTuple):
    index: int
    interface_name: str
    packets_sent: Union[Literal["N/A"], int]
    packets_recv: Union[Literal["N/A"], int]
    ip_address: Union[Literal["N/A"], str]
    mac_address: Union[Literal["N/A"], str]
    adapter_name: Union[Literal["N/A"], str]
    manufacturer: Union[Literal["N/A"], str]
    is_arp: bool = False

class InterfaceSelectionDialog(QDialog):
    def __init__(self, screen_width: int, screen_height: int, interfaces: list[InterfaceSelectionData]):
        super().__init__()

        # Set up the window
        self.setWindowTitle("Capture Network Interface Selection - Session Sniffer")
        # Set a minimum size for the window
        self.setMinimumSize(800, 600)
        self.resize_window_for_screen(screen_width, screen_height)

        # Custom variables
        self.selected_interface_data = None
        self.interfaces = interfaces  # Store the list of interface data

        # Layout for the dialog
        layout = QVBoxLayout()

        # Table widget for displaying interfaces
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["Interface Name", "Packets Sent", "Packets Received", "IP Address", "MAC Address", "Adapter Name", "Manufacturer"]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        # Populate the table with interface data
        for idx, interface in enumerate(self.interfaces):
            self.table.insertRow(idx)

            item = QTableWidgetItem(interface.interface_name if not interface.is_arp else f"{interface.interface_name} (ARP)")
            self.table.setItem(idx, 0, item)

            item = QTableWidgetItem(str(interface.packets_sent))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(idx, 1, item)

            item = QTableWidgetItem(str(interface.packets_recv))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(idx, 2, item)

            item = QTableWidgetItem(interface.ip_address)
            self.table.setItem(idx, 3, item)

            item = QTableWidgetItem(interface.mac_address)
            self.table.setItem(idx, 4, item)

            item = QTableWidgetItem(interface.adapter_name)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(idx, 5, item)

            item = QTableWidgetItem(interface.manufacturer)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(idx, 6, item)

        # Bottom layout for buttons
        bottom_layout = QHBoxLayout()
        instruction_label = QLabel("Select the network interface you want to sniff.")
        instruction_label.setStyleSheet("font-size: 15pt;")

        self.select_button = QPushButton("Start Sniffing")
        self.select_button.setStyleSheet("font-size: 18pt;")
        self.select_button.setEnabled(False)  # Initially disabled

        # Set fixed size for the button
        self.select_button.setFixedSize(300, 50)  # Adjusted width and height for slightly larger button

        self.select_button.clicked.connect(self.select_interface)

        bottom_layout.addWidget(instruction_label)
        bottom_layout.addWidget(self.select_button)

        # Center the button in the layout
        bottom_layout.setAlignment(instruction_label, Qt.AlignmentFlag.AlignCenter)
        bottom_layout.setAlignment(self.select_button, Qt.AlignmentFlag.AlignCenter)

        # Add widgets to layout
        layout.addWidget(self.table)
        layout.addLayout(bottom_layout)
        self.setLayout(layout)

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Connect selection change signal to enable/disable Select button
        self.table.selectionModel().selectionChanged.connect(self.update_select_button_state)

    def resize_window_for_screen(self, screen_width: int, screen_height: int):
        # Resize the window based on screen size
        if screen_width >= 2560 and screen_height >= 1440:
            self.resize(1400, 900)
        elif screen_width >= 1920 and screen_height >= 1080:
            self.resize(1200, 720)
        elif screen_width >= 1024 and screen_height >= 768:
            self.resize(940, 680)

    def update_select_button_state(self):
        # Check if any row is selected
        selected_row = self.table.currentRow()
        if selected_row != -1:
            self.select_button.setEnabled(True)  # Enable the Select button
        else:
            self.select_button.setEnabled(False)  # Disable the Select button

    def select_interface(self):
        selected_row = self.table.currentRow()
        if selected_row != -1:
            # Retrieve the selected interface data
            self.selected_interface_data = self.interfaces[selected_row]  # Get the selected interface data
            self.accept()  # Close the dialog and set its result to QDialog.Accepted


def show_interface_selection_dialog(screen_width: int, screen_height: int, interfaces: list[InterfaceSelectionData]):
    # Create and show the interface selection dialog
    dialog = InterfaceSelectionDialog(screen_width, screen_height, interfaces)
    if dialog.exec() == QDialog.DialogCode.Accepted:  # Blocks until the dialog is accepted or rejected
        return dialog.selected_interface_data
    else:
        return None
