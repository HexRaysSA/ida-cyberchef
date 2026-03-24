"""Persistent operation browser widget with search and documentation."""

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ida_cyberchef.core.operation_doc_formatter import format_operation_docs
from ida_cyberchef.core.operation_registry import OperationRegistry


class OperationBrowserWidget(QWidget):
    """Persistent widget for browsing and inserting operations.

    Layout:
    ┌─ Operation Browser ────────────────────────────────────────────────┐
    │ ┌─ Search ──────────────────────────────────────────────────────┐ │
    │ │ Search operations...                                          │ │
    │ └───────────────────────────────────────────────────────────────┘ │
    │ ┌─────────────────────────┬─────────────────────────────────────┐ │
    │ │ To Base64               │ **To Base64**                       │ │
    │ │ From Base64             │ Category: Data format               │ │
    │ │ To Hex                  │                                     │ │
    │ │ From Hex                │ Converts data to Base64 encoding.  │ │
    │ │ XOR                     │                                     │ │
    │ │ AES Decrypt             │ Parameters:                         │ │
    │ │ (more operations...)    │   Alphabet (option) - ...           │ │
    │ └─────────────────────────┴─────────────────────────────────────┘ │
    └───────────────────────────────────────────────────────────────────┘
    """

    operation_selected = Signal(dict)

    def __init__(self, registry: OperationRegistry, parent=None):
        super().__init__(parent)

        self._registry = registry
        self._search_timer = QTimer()
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(100)
        self._search_timer.timeout.connect(self._perform_search)

        self._setup_ui()
        self._populate_default_view()

    def _setup_ui(self):
        """Setup widget UI structure."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 6)
        layout.setSpacing(4)

        # Search bar
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search operations...")
        self._search_input.setStyleSheet("padding: 4px 8px;")
        self._search_input.textChanged.connect(self._on_search_changed)
        layout.addWidget(self._search_input)

        # Splitter with list and docs
        splitter = QSplitter(Qt.Horizontal)

        # Operation list (left)
        self._operation_list = QListWidget()
        self._operation_list.itemDoubleClicked.connect(self._on_operation_double_clicked)
        self._operation_list.currentItemChanged.connect(self._on_current_item_changed)
        self._operation_list.itemEntered.connect(self._on_item_hovered)
        self._operation_list.setMouseTracking(True)
        splitter.addWidget(self._operation_list)

        # Documentation panel (right)
        self._doc_panel = QPlainTextEdit()
        self._doc_panel.setReadOnly(True)
        self._doc_panel.setPlainText(
            "Hover over an operation to see documentation.\n\nKeyboard shortcuts:\n  Up/Down: Navigate\n  Enter: Add operation\n  Escape: Clear search\n  Ctrl+F or /: Focus search"
        )
        splitter.addWidget(self._doc_panel)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

        self._search_input.setFocus()

    def _populate_default_view(self):
        """Populate list with favorites first, then all operations by category."""
        self._operation_list.clear()

        operations = self._registry.get_all_operations()

        # Favorites first
        favorites = [op for op in operations if op.get("is_favorite", False)]
        for op in favorites:
            self._add_operation_item(op)

        # All operations grouped by category
        from itertools import groupby

        operations_sorted = sorted(operations, key=lambda op: op.get("category", "Other"))
        for category, ops_iter in groupby(operations_sorted, key=lambda op: op.get("category", "Other")):
            for op in ops_iter:
                self._add_operation_item(op)

    def _add_operation_item(self, operation: dict):
        """Add operation to list."""
        item = QListWidgetItem(operation["name"])
        item.setData(Qt.UserRole, operation)
        self._operation_list.addItem(item)

    def _on_search_changed(self, text: str):
        """Handle search text changes with debouncing."""
        self._search_timer.stop()
        self._search_timer.start()

    def _perform_search(self):
        """Perform the actual search operation."""
        text = self._search_input.text().strip()
        self._operation_list.clear()

        if not text:
            self._populate_default_view()
            return

        results = self._registry.search_operations(text)
        if not results:
            item = QListWidgetItem(f"No operations match '{text}'")
            item.setFlags(Qt.NoItemFlags)
            self._operation_list.addItem(item)
        else:
            for op in results:
                self._add_operation_item(op)
            self._operation_list.setCurrentRow(0)

    def _on_current_item_changed(self, current: QListWidgetItem, previous: QListWidgetItem):
        """Handle current item changed (for keyboard navigation)."""
        if current and current.data(Qt.UserRole):
            self._update_documentation(current.data(Qt.UserRole))

    def _on_item_hovered(self, item: QListWidgetItem):
        """Handle mouse hover over item."""
        if item and item.data(Qt.UserRole):
            # Set this item as current when hovering over it
            index = self._operation_list.row(item)
            if index >= 0:
                self._operation_list.setCurrentRow(index)
            self._update_documentation(item.data(Qt.UserRole))

    def _update_documentation(self, operation: dict):
        """Update documentation panel with operation info."""
        doc_text = format_operation_docs(operation)
        self._doc_panel.setPlainText(doc_text)

    def _on_operation_double_clicked(self, item: QListWidgetItem):
        """Handle double-click on operation."""
        operation = item.data(Qt.UserRole)
        if operation:
            self.operation_selected.emit(operation)
            self._search_input.setFocus()

    def keyPressEvent(self, event):
        """Handle keyboard shortcuts."""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            current_item = self._operation_list.currentItem()
            if current_item and current_item.data(Qt.UserRole):
                self._on_operation_double_clicked(current_item)
        elif event.key() == Qt.Key_Escape:
            self._search_input.clear()
            self._search_input.setFocus()
        elif event.key() == Qt.Key_Slash or (event.key() == Qt.Key_F and event.modifiers() == Qt.ControlModifier):
            self._search_input.setFocus()
            self._search_input.selectAll()
        else:
            super().keyPressEvent(event)
