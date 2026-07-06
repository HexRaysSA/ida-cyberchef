"""Dialog for searching and selecting operations."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)

from ida_cyberchef.core.operation_registry import OperationRegistry


class OperationSearchDialog(QDialog):
    """Dialog for fuzzy searching operations.

    Layout:
    ┌─ Select Operation ────────────────────────────────────────────────┐
    │ ┌─ Search Input ────────────────────────────────────────────────┐ │
    │ │ Search operations...                                          │ │
    │ └───────────────────────────────────────────────────────────────┘ │
    │ ┌─ Results List ────────────────────────────────────────────────┐ │
    │ │ To Base64                                                     │ │
    │ │ From Base64                                                   │ │
    │ │ To Hex                                                        │ │
    │ │ From Hex                                                      │ │
    │ │ XOR                                                           │ │
    │ │ AES Decrypt                                                   │ │
    │ │ (more operations...)                                          │ │
    │ │                                                               │ │
    │ └───────────────────────────────────────────────────────────────┘ │
    │                                            [Select] [Cancel]      │
    └───────────────────────────────────────────────────────────────────┘
    """

    operation_selected = Signal(dict)

    def __init__(self, registry: OperationRegistry, parent=None):
        super().__init__(parent)

        self._registry = registry
        self._selected_operation = None

        self.setWindowTitle("Select Operation")
        self.resize(300, 400)

        self._setup_ui()
        self._populate_all_operations()

    def _setup_ui(self):
        """Setup dialog UI."""
        layout = QVBoxLayout(self)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search operations...")
        self._search_input.textChanged.connect(self._on_search_changed)
        layout.addWidget(self._search_input)

        self._results_list = QListWidget()
        self._results_list.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self._results_list)

        button_layout = QHBoxLayout()

        self._select_button = QPushButton("Select")
        self._select_button.clicked.connect(self._on_select_clicked)
        button_layout.addWidget(self._select_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

        self._search_input.setFocus()

    def _populate_all_operations(self):
        """Populate list with all operations."""
        self._results_list.clear()

        operations = self._registry.get_all_operations()
        for op in operations:
            item = QListWidgetItem(op["name"])
            item.setData(Qt.UserRole, op)
            self._results_list.addItem(item)

    def _on_search_changed(self, text: str):
        """Handle search text changes."""
        self._results_list.clear()

        if not text.strip():
            self._populate_all_operations()
            return

        results = self._registry.search_operations(text)
        for op in results:
            item = QListWidgetItem(op["name"])
            item.setData(Qt.UserRole, op)
            self._results_list.addItem(item)

        if self._results_list.count() > 0:
            self._results_list.setCurrentRow(0)

    def _on_item_double_clicked(self, item: QListWidgetItem):
        """Handle double-click on item."""
        self._selected_operation = item.data(Qt.UserRole)
        self.accept()

    def _on_select_clicked(self):
        """Handle select button click."""
        current_item = self._results_list.currentItem()
        if current_item:
            self._selected_operation = current_item.data(Qt.UserRole)
            self.accept()

    def get_selected_operation(self) -> dict | None:
        """Get selected operation.

        Returns: Operation dict or None if cancelled
        """
        return self._selected_operation

    def keyPressEvent(self, event):
        """Handle key presses."""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            self._on_select_clicked()
        else:
            super().keyPressEvent(event)
