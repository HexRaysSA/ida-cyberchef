"""Standalone Qt application for CyberChef widget."""

import sys

from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow, QMessageBox

from ida_cyberchef.cyberchef_widget import CyberChefWidget


class CyberChefMainWindow(QMainWindow):
    """Main window wrapper for standalone application."""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("CyberChef")
        self.resize(288, 600)

        self._widget = CyberChefWidget()
        self.setCentralWidget(self._widget)

        self._setup_menu()

    def _setup_menu(self):
        """Setup menu bar."""
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")

        load_action = QAction("Load Recipe...", self)
        load_action.setShortcut(QKeySequence.Open)
        load_action.triggered.connect(self._load_recipe)
        file_menu.addAction(load_action)

        save_action = QAction("Save Recipe...", self)
        save_action.setShortcut(QKeySequence.Save)
        save_action.triggered.connect(self._save_recipe)
        file_menu.addAction(save_action)

        file_menu.addSeparator()

        quit_action = QAction("Quit", self)
        quit_action.setShortcut(QKeySequence.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

    def _load_recipe(self):
        """Load recipe from file."""
        filename, _ = QFileDialog.getOpenFileName(self, "Load Recipe", "", "Recipe Files (*.json)")

        if filename:
            try:
                self._widget.load_recipe_from_file(filename)
                QMessageBox.information(self, "Success", f"Recipe loaded from {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error loading recipe: {e}")

    def _save_recipe(self):
        """Save recipe to file."""
        filename, _ = QFileDialog.getSaveFileName(self, "Save Recipe", "", "Recipe Files (*.json)")

        if filename:
            try:
                self._widget.save_recipe_to_file(filename)
                QMessageBox.information(self, "Success", f"Recipe saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error saving recipe: {e}")


def main():
    """Main application entry point."""
    app = QApplication(sys.argv)

    window = CyberChefMainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
