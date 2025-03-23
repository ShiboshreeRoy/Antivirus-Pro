import os
import sys
import hashlib
import shutil
import threading
import queue
import logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLabel, QProgressBar, QMessageBox, QTableWidget, 
                             QTableWidgetItem, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from concurrent.futures import ThreadPoolExecutor

# Configuration
QUARANTINE_DIR = os.path.expanduser("~/Malware_Quarantine")
LOG_FILE = "antivirus_log.txt"
WHITELIST = {"trusted_file.exe", "safe_app.dll"}  # Files to ignore
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.cmd', '.dll', '.scr', '.js', '.vbs', '.ps1', '.jar']
THREAD_COUNT = max(os.cpu_count() or 4, 8)  # Use multiple threads for scanning

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Example known malware hashes (replace with a real database in production)
KNOWN_MALWARE_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",  # Example MD5 hash
    "e99a18c428cb38d5f260853678922e03"   # Example SHA-1 hash
}

class QuarantineManager:
    """Manages the quarantine of suspicious files."""
    def __init__(self, quarantine_dir=QUARANTINE_DIR):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine_file(self, file_path, file_hash):
        """Move a file to the quarantine directory."""
        try:
            dest_path = os.path.join(self.quarantine_dir, f"{file_hash}_{os.path.basename(file_path)}")
            shutil.move(file_path, dest_path)
            logging.info(f"Quarantined: {file_path} -> {dest_path}")
            return dest_path
        except Exception as e:
            logging.error(f"Failed to quarantine {file_path}: {e}")
            return None

    def delete_file(self, file_path):
        """Permanently delete a file."""
        try:
            os.remove(file_path)
            logging.info(f"Deleted: {file_path}")
        except Exception as e:
            logging.error(f"Failed to delete {file_path}: {e}")

class Scanner:
    """Handles scanning for malware using signatures and heuristics."""
    def __init__(self, known_hashes=KNOWN_MALWARE_HASHES, suspicious_extensions=SUSPICIOUS_EXTENSIONS):
        self.known_hashes = known_hashes
        self.suspicious_extensions = suspicious_extensions

    def calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(16384):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logging.error(f"Failed to hash {file_path}: {e}")
            return None

    def is_suspicious_file(self, file_path):
        """Heuristic check for suspicious files."""
        file_name = os.path.basename(file_path)
        if len(file_name.split('.')) > 2:  # Double extensions (e.g., file.exe.exe)
            return True
        temp_dirs = ['temp', 'tmp', '/tmp', '/var/tmp']
        if any(temp_dir in file_path.lower() for temp_dir in temp_dirs):
            return True
        return False

    def scan_directory(self, directory, progress_callback, result_callback):
        """Scan a directory for malware."""
        files_to_scan = []
        malware_files = []
        scan_queue = queue.Queue()
        scanned_count = 0

        # Collect files to scan
        for root, _, files in os.walk(directory):
            for file in files:
                files_to_scan.append(os.path.join(root, file))

        total_files = len(files_to_scan)
        for file_path in files_to_scan:
            scan_queue.put(file_path)

        def worker():
            nonlocal scanned_count
            while True:
                try:
                    file_path = scan_queue.get_nowait()
                    if os.path.basename(file_path) in WHITELIST:
                        scan_queue.task_done()
                        continue

                    file_hash = self.calculate_hash(file_path)
                    if not file_hash:
                        scan_queue.task_done()
                        continue

                    # Check for known malware hashes
                    if file_hash in self.known_hashes:
                        malware_files.append((file_path, file_hash, "Known Malware"))
                    # Check for suspicious extensions or heuristics
                    elif (os.path.splitext(file_path)[1].lower() in self.suspicious_extensions or
                          self.is_suspicious_file(file_path)):
                        malware_files.append((file_path, file_hash, "Suspicious File"))

                    scan_queue.task_done()
                    scanned_count += 1
                    progress_callback(scanned_count, total_files)
                except queue.Empty:
                    break
                except Exception as e:
                    logging.error(f"Error scanning {file_path}: {e}")
                    scan_queue.task_done()

        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
            for _ in range(THREAD_COUNT):
                executor.submit(worker)

        scan_queue.join()
        result_callback(malware_files)

class ScanWorker(QThread):
    """Worker thread for scanning."""
    progress = pyqtSignal(int, int)
    result = pyqtSignal(list)

    def __init__(self, scanner, directory):
        super().__init__()
        self.scanner = scanner
        self.directory = directory

    def run(self):
        self.scanner.scan_directory(self.directory, self.progress.emit, self.result.emit)

class AntivirusGUI(QMainWindow):
    """Main GUI for the antivirus tool with an Apple iOS-like theme."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Antivirus Pro")
        self.setGeometry(100, 100, 800, 600)
        self.scanner = Scanner()
        self.quarantine_manager = QuarantineManager()
        self.init_ui()

    def init_ui(self):
        # Main widget and layout
        main_widget = QWidget(self)
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Directory selection
        dir_layout = QHBoxLayout()
        self.dir_label = QLabel("Target Directory: Not selected")
        dir_button = QPushButton("Select Directory")
        dir_button.clicked.connect(self.select_directory)
        dir_layout.addWidget(self.dir_label)
        dir_layout.addWidget(dir_button)
        layout.addLayout(dir_layout)

        # Scan button
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Malware table
        self.malware_table = QTableWidget()
        self.malware_table.setColumnCount(3)
        self.malware_table.setHorizontalHeaderLabels(["File Path", "Hash", "Reason"])
        self.malware_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.malware_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.malware_table)

        # Action buttons
        action_layout = QHBoxLayout()
        self.quarantine_button = QPushButton("Quarantine Selected")
        self.quarantine_button.clicked.connect(self.quarantine_files)
        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.clicked.connect(self.delete_files)
        action_layout.addWidget(self.quarantine_button)
        action_layout.addWidget(self.delete_button)
        layout.addLayout(action_layout)

        # Apple iOS-like styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: #007aff;
                color: white;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QLabel {
                color: #333;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #ccc;
            }
            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 5px;
                text-align: center;
            }
        """)

        self.target_directory = None

    def select_directory(self):
        """Select the directory to scan."""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory", os.path.expanduser("~"))
        if directory:
            self.target_directory = directory
            self.dir_label.setText(f"Target Directory: {directory}")

    def start_scan(self):
        """Start the scanning process."""
        if not self.target_directory:
            QMessageBox.warning(self, "Error", "Please select a directory first!")
            return

        self.scan_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.malware_table.setRowCount(0)
        self.worker = ScanWorker(self.scanner, self.target_directory)
        self.worker.progress.connect(self.update_progress)
        self.worker.result.connect(self.scan_finished)
        self.worker.start()

    def update_progress(self, scanned, total):
        """Update the progress bar."""
        self.progress_bar.setValue(int((scanned / total) * 100))

    def scan_finished(self, malware_files):
        """Handle scan completion."""
        self.scan_button.setEnabled(True)
        if malware_files:
            self.populate_malware_table(malware_files)
        else:
            QMessageBox.information(self, "Scan Complete", "No malware found.")

    def populate_malware_table(self, malware_files):
        """Display detected malware in the table."""
        self.malware_table.setRowCount(len(malware_files))
        for row, (file_path, file_hash, reason) in enumerate(malware_files):
            self.malware_table.setItem(row, 0, QTableWidgetItem(file_path))
            self.malware_table.setItem(row, 1, QTableWidgetItem(file_hash))
            self.malware_table.setItem(row, 2, QTableWidgetItem(reason))

    def quarantine_files(self):
        """Quarantine selected files."""
        selected_rows = self.malware_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "No files selected!")
            return

        reply = QMessageBox.question(self, "Confirm", "Quarantine selected files?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            for row in selected_rows:
                file_path = self.malware_table.item(row.row(), 0).text()
                file_hash = self.malware_table.item(row.row(), 1).text()
                dest_path = self.quarantine_manager.quarantine_file(file_path, file_hash)
                if dest_path:
                    self.malware_table.removeRow(row.row())

    def delete_files(self):
        """Delete selected files permanently."""
        selected_rows = self.malware_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "No files selected!")
            return

        reply = QMessageBox.question(self, "Confirm", "Delete selected files permanently?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            for row in selected_rows:
                file_path = self.malware_table.item(row.row(), 0).text()
                self.quarantine_manager.delete_file(file_path)
                self.malware_table.removeRow(row.row())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AntivirusGUI()
    window.show()
    sys.exit(app.exec_())