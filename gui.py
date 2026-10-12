"""Packet Monitoring Application - Graphical User Interface (GUI).

A modern, multi-pane packet analyzer built with PyQt6 and Scapy.
Features real-time capture, BPF filtering, PCAP/JSON/CSV export,
protocol tree inspector, and hex dump view.
"""

import os
import platform
import sys
from datetime import datetime

from PyQt6.QtCore import QObject, QThread, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from scapy.all import conf, rdpcap, sniff, wrpcap
from scapy.packet import Packet

import monitor

DARK_STYLESHEET = """
QMainWindow {
    background-color: #121316;
}
QWidget {
    background-color: #121316;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
}
QGroupBox {
    border: 1px solid #2d3748;
    border-radius: 8px;
    margin-top: 8px;
    padding-top: 10px;
    font-weight: bold;
    color: #94a3b8;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QLineEdit, QComboBox {
    background-color: #1e222b;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 10px;
    color: #f8fafc;
    selection-background-color: #3b82f6;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #3b82f6;
}
QComboBox QAbstractItemView {
    background-color: #1e222b;
    border: 1px solid #334155;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
}
QPushButton {
    background-color: #2563eb;
    color: #ffffff;
    font-weight: 600;
    border: none;
    border-radius: 6px;
    padding: 7px 16px;
}
QPushButton:hover {
    background-color: #1d4ed8;
}
QPushButton:pressed {
    background-color: #1e40af;
}
QPushButton:disabled {
    background-color: #334155;
    color: #64748b;
}
QPushButton#startBtn {
    background-color: #059669;
}
QPushButton#startBtn:hover {
    background-color: #047857;
}
QPushButton#stopBtn {
    background-color: #dc2626;
}
QPushButton#stopBtn:hover {
    background-color: #b91c1c;
}
QPushButton#clearBtn {
    background-color: #374151;
}
QPushButton#clearBtn:hover {
    background-color: #4b5563;
}
QTableWidget {
    background-color: #181b22;
    border: 1px solid #282f3d;
    border-radius: 6px;
    gridline-color: #232936;
    selection-background-color: #1e3a8a;
    selection-color: #ffffff;
}
QTableWidget::item {
    padding: 4px;
}
QHeaderView::section {
    background-color: #1f242e;
    color: #94a3b8;
    padding: 6px;
    border: none;
    border-right: 1px solid #282f3d;
    border-bottom: 1px solid #282f3d;
    font-weight: 600;
}
QTreeWidget, QPlainTextEdit {
    background-color: #181b22;
    border: 1px solid #282f3d;
    border-radius: 6px;
    color: #e2e8f0;
}
QTreeWidget::item:selected {
    background-color: #1e3a8a;
}
QSplitter::handle {
    background-color: #282f3d;
    height: 3px;
    width: 3px;
}
QMenuBar {
    background-color: #121316;
    border-bottom: 1px solid #282f3d;
}
QMenuBar::item {
    padding: 6px 12px;
}
QMenuBar::item:selected {
    background-color: #1e222b;
}
QMenu {
    background-color: #1e222b;
    border: 1px solid #334155;
}
QMenu::item {
    padding: 6px 20px;
}
QMenu::item:selected {
    background-color: #3b82f6;
}
QStatusBar {
    background-color: #121316;
    border-top: 1px solid #282f3d;
    color: #94a3b8;
}
"""

PROTOCOL_COLORS = {
    "TCP": QColor("#38bdf8"),
    "UDP": QColor("#fbbf24"),
    "ICMP": QColor("#e879f9"),
    "ICMPv6": QColor("#e879f9"),
    "ARP": QColor("#34d399"),
    "IPv4": QColor("#93c5fd"),
    "IPv6": QColor("#c084fc"),
}


def format_hex_dump(raw_bytes: bytes) -> str:
    """Return a Wireshark-like 16-byte hex + ASCII dump."""
    if not raw_bytes:
        return "(No payload or empty frame)"
    lines = []
    for offset in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[offset : offset + 16]
        hex_p1 = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_p2 = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_str = f"{hex_p1:<23}  {hex_p2:<23}"
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}   {hex_str}   {ascii_str}")
    return "\n".join(lines)


class CaptureWorker(QThread):
    """Background worker thread executing Scapy packet sniff."""

    packet_captured = pyqtSignal(object, dict)
    capture_error = pyqtSignal(str)
    capture_finished = pyqtSignal(int)

    def __init__(self, iface: str, bpf_filter: str = ""):
        super().__init__()
        self.iface = iface
        self.bpf_filter = bpf_filter.strip()
        self.is_running = True
        self.count = 0

    def run(self):
        def _on_packet(pkt: Packet):
            if not self.is_running:
                return
            self.count += 1
            record = monitor.extract_record(self.count, pkt)
            self.packet_captured.emit(pkt, record)

        kwargs = {
            "iface": self.iface,
            "prn": _on_packet,
            "store": False,
            "timeout": 0.5,
        }
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter

        try:
            while self.is_running:
                sniff(**kwargs)
        except PermissionError:
            self.capture_error.emit("Permission Denied: Capturing packets requires elevated privileges (sudo/Administrator).")
        except Exception as exc:
            err = str(exc)
            if "syntax error" in err.lower() or "bpf" in err.lower():
                self.capture_error.emit(f"Invalid BPF filter expression '{self.bpf_filter}': {err}")
            elif any(w in err.lower() for w in ("permission", "operation not permitted")):
                self.capture_error.emit("Permission Denied: Run application with elevated privileges (sudo or Administrator).")
            else:
                self.capture_error.emit(f"Capture error on interface '{self.iface}': {err}")
        finally:
            self.capture_finished.emit(self.count)

    def stop(self):
        self.is_running = False


class PacketMonitorGUI(QMainWindow):
    """Main Application Window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Monitor - Network Frame Analysis System")
        self.resize(1150, 750)
        self.setStyleSheet(DARK_STYLESHEET)

        self.captured_packets = []
        self.captured_records = []
        self.worker = None

        self._init_ui()
        self._populate_interfaces()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # Control Bar
        ctrl_group = QGroupBox("Capture Controls")
        ctrl_layout = QHBoxLayout(ctrl_group)
        ctrl_layout.setContentsMargins(12, 12, 12, 12)
        ctrl_layout.setSpacing(10)

        # Interface Combo
        ctrl_layout.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(220)
        ctrl_layout.addWidget(self.iface_combo)

        # Filter Input
        ctrl_layout.addWidget(QLabel("BPF Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g. tcp port 80, udp, icmp, host 192.168.1.1")
        self.filter_input.setMinimumWidth(260)
        ctrl_layout.addWidget(self.filter_input)

        # Buttons
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self.start_capture)
        ctrl_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_capture)
        ctrl_layout.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setObjectName("clearBtn")
        self.clear_btn.clicked.connect(self.clear_capture)
        ctrl_layout.addWidget(self.clear_btn)

        self.auto_scroll_cb = QCheckBox("Auto-scroll")
        self.auto_scroll_cb.setChecked(True)
        ctrl_layout.addWidget(self.auto_scroll_cb)

        main_layout.addWidget(ctrl_group)

        # Quick Filter / Search Bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search Display:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter current table by IP, port, protocol or keyword...")
        self.search_input.textChanged.connect(self._filter_table_view)
        search_layout.addWidget(self.search_input)
        main_layout.addLayout(search_layout)

        # Splitters for Table and Detail Panes
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        # Table Widget
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Summary"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        main_splitter.addWidget(self.table)

        # Lower Detail Splitter (Tree & Hex)
        detail_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Tree Pane
        tree_container = QWidget()
        tree_layout = QVBoxLayout(tree_container)
        tree_layout.setContentsMargins(0, 0, 0, 0)
        tree_layout.addWidget(QLabel("<b>Packet Dissection (Layers & Fields):</b>"))
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["Field", "Value"])
        self.detail_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.detail_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tree_layout.addWidget(self.detail_tree)
        detail_splitter.addWidget(tree_container)

        # Hex Pane
        hex_container = QWidget()
        hex_layout = QVBoxLayout(hex_container)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.addWidget(QLabel("<b>Hex & ASCII Payload Dump:</b>"))
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        mono_font = QFont("Courier" if platform.system() == "Windows" else "monospace", 10)
        self.hex_view.setFont(mono_font)
        hex_layout.addWidget(self.hex_view)
        detail_splitter.addWidget(hex_container)

        detail_splitter.setSizes([550, 600])
        main_splitter.addWidget(detail_splitter)
        main_splitter.setSizes([450, 300])

        main_layout.addWidget(main_splitter)

        # Status Bar
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Ready")
        self.packet_count_label = QLabel("Packets: 0")
        self.status_bar.addWidget(self.status_label, 1)
        self.status_bar.addPermanentWidget(self.packet_count_label)

        self._create_menus()

    def _create_menus(self):
        menubar = self.menuBar()

        # File Menu
        file_menu = menubar.addMenu("&File")

        open_pcap_act = QAction("Open PCAP File...", self)
        open_pcap_act.setShortcut("Ctrl+O")
        open_pcap_act.triggered.connect(self.open_pcap)
        file_menu.addAction(open_pcap_act)

        open_json_act = QAction("Import JSON...", self)
        open_json_act.triggered.connect(self.open_json)
        file_menu.addAction(open_json_act)

        open_csv_act = QAction("Import CSV...", self)
        open_csv_act.triggered.connect(self.open_csv)
        file_menu.addAction(open_csv_act)

        file_menu.addSeparator()

        save_pcap_act = QAction("Export to PCAP...", self)
        save_pcap_act.setShortcut("Ctrl+S")
        save_pcap_act.triggered.connect(self.export_pcap)
        file_menu.addAction(save_pcap_act)

        save_json_act = QAction("Export to JSON...", self)
        save_json_act.triggered.connect(self.export_json_file)
        file_menu.addAction(save_json_act)

        save_csv_act = QAction("Export to CSV...", self)
        save_csv_act.triggered.connect(self.export_csv_file)
        file_menu.addAction(save_csv_act)

        file_menu.addSeparator()

        exit_act = QAction("Exit", self)
        exit_act.setShortcut("Ctrl+Q")
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        # Capture Menu
        cap_menu = menubar.addMenu("&Capture")

        start_act = QAction("Start Capture", self)
        start_act.setShortcut("Ctrl+R")
        start_act.triggered.connect(self.start_capture)
        cap_menu.addAction(start_act)

        stop_act = QAction("Stop Capture", self)
        stop_act.setShortcut("Ctrl+T")
        stop_act.triggered.connect(self.stop_capture)
        cap_menu.addAction(stop_act)

        clear_act = QAction("Clear All", self)
        clear_act.setShortcut("Ctrl+L")
        clear_act.triggered.connect(self.clear_capture)
        cap_menu.addAction(clear_act)

        # Help Menu
        help_menu = menubar.addMenu("&Help")
        about_act = QAction("About Packet Monitor", self)
        about_act.triggered.connect(self._show_about)
        help_menu.addAction(about_act)

    def _populate_interfaces(self):
        self.iface_combo.clear()
        try:
            entries = monitor.list_capture_interfaces()
        except Exception:
            entries = []

        default_name = monitor.default_network_name()
        default_idx = 0

        for idx, iface in enumerate(entries):
            name = getattr(iface, "network_name", getattr(iface, "name", str(iface)))
            ipv4_list = monitor.iface_ipv4(iface)
            ip_str = f" ({', '.join(ipv4_list)})" if ipv4_list else ""
            desc = getattr(iface, "description", name) or name
            label = f"{desc}{ip_str}"

            self.iface_combo.addItem(label, userData=name)
            if name == default_name:
                default_idx = idx

        if entries:
            self.iface_combo.setCurrentIndex(default_idx)
        else:
            self.iface_combo.addItem("No interfaces detected", userData="")

    def start_capture(self):
        if self.worker and self.worker.isRunning():
            return

        iface = self.iface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "No Interface", "Please select a valid network interface to capture on.")
            return

        bpf = self.filter_input.text().strip()

        self.worker = CaptureWorker(iface, bpf)
        self.worker.packet_captured.connect(self._on_packet_captured)
        self.worker.capture_error.connect(self._on_capture_error)
        self.worker.capture_finished.connect(self._on_capture_finished)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.filter_input.setEnabled(False)

        filter_msg = f" [Filter: {bpf}]" if bpf else ""
        self.status_label.setText(f"● Capturing on {iface}{filter_msg}...")
        self.worker.start()

    def stop_capture(self):
        if self.worker and self.worker.isRunning():
            self.status_label.setText("Stopping capture...")
            self.worker.stop()

    def _on_capture_finished(self, count):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.filter_input.setEnabled(True)
        self.status_label.setText("Capture stopped.")

    def _on_capture_error(self, message):
        self.stop_capture()
        QMessageBox.critical(self, "Capture Error", message)

    def _on_packet_captured(self, pkt, record):
        self.captured_packets.append(pkt)
        self.captured_records.append(record)

        row = self.table.rowCount()
        self.table.insertRow(row)

        src = str(record.get("src_ip", "") or record.get("eth_src", ""))
        dst = str(record.get("dst_ip", "") or record.get("eth_dst", ""))
        if record.get("src_port"):
            src += f":{record['src_port']}"
        if record.get("dst_port"):
            dst += f":{record['dst_port']}"

        ts_text = str(record.get("timestamp", ""))
        if " " in ts_text:
            ts_text = ts_text.split(" ")[-1]

        items = [
            QTableWidgetItem(str(record.get("frame_no", ""))),
            QTableWidgetItem(ts_text),
            QTableWidgetItem(src),
            QTableWidgetItem(dst),
            QTableWidgetItem(str(record.get("protocol", "Unknown"))),
            QTableWidgetItem(str(record.get("length", ""))),
            QTableWidgetItem(str(record.get("summary", ""))),
        ]

        color = PROTOCOL_COLORS.get(record.get("protocol"))
        if color:
            items[4].setForeground(color)

        for col, it in enumerate(items):
            it.setFlags(it.flags() ^ Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, col, it)

        self.packet_count_label.setText(f"Packets: {len(self.captured_records)}")

        if self.auto_scroll_cb.isChecked():
            self.table.scrollToBottom()

    def _on_row_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        pkt = self.captured_packets[row] if 0 <= row < len(self.captured_packets) else None
        rec = self.captured_records[row] if 0 <= row < len(self.captured_records) else None
        if pkt:
            self._display_packet_details(pkt)
        elif rec:
            self._display_record_details(rec)

    def _display_packet_details(self, pkt: Packet):
        self.detail_tree.clear()

        # Build Layer Tree
        current_layer = pkt
        while current_layer:
            layer_name = current_layer.name
            root_item = QTreeWidgetItem(self.detail_tree, [layer_name, ""])
            root_item.setExpanded(True)

            for field in current_layer.fields_desc:
                val = current_layer.getfieldval(field.name)
                rep = current_layer.sprintf(f"%{layer_name}.{field.name}%") if hasattr(current_layer, "sprintf") else str(val)
                QTreeWidgetItem(root_item, [field.name, str(rep)])

            current_layer = current_layer.payload if hasattr(current_layer, "payload") and current_layer.payload != b"" else None

        # Format Hex Dump
        raw_bytes = bytes(pkt)
        self.hex_view.setPlainText(format_hex_dump(raw_bytes))

    def _display_record_details(self, record: dict):
        self.detail_tree.clear()

        # Frame item
        frame_item = QTreeWidgetItem(self.detail_tree, [f"Frame #{record.get('frame_no', '?')}", ""])
        frame_item.setExpanded(True)
        for k in ["frame_no", "timestamp", "protocol", "length", "summary"]:
            if record.get(k) is not None:
                QTreeWidgetItem(frame_item, [k, str(record.get(k))])

        # Ethernet item
        if record.get("eth_src") or record.get("eth_dst") or record.get("eth_type"):
            eth_item = QTreeWidgetItem(self.detail_tree, ["Ethernet", ""])
            eth_item.setExpanded(True)
            for k in ["eth_src", "eth_dst", "eth_type", "eth_type_name"]:
                if record.get(k):
                    QTreeWidgetItem(eth_item, [k, str(record.get(k))])

        # Network/Transport item
        proto_name = str(record.get("protocol") or "Network")
        net_item = QTreeWidgetItem(self.detail_tree, [proto_name, ""])
        net_item.setExpanded(True)
        for k in ["src_ip", "dst_ip", "src_port", "dst_port", "ttl"]:
            if record.get(k):
                QTreeWidgetItem(net_item, [k, str(record.get(k))])

        # Payload item
        if record.get("payload_bytes") or record.get("payload_preview"):
            payload_item = QTreeWidgetItem(self.detail_tree, ["Payload", ""])
            payload_item.setExpanded(True)
            for k in ["payload_bytes", "payload_preview"]:
                if record.get(k):
                    QTreeWidgetItem(payload_item, [k, str(record.get(k))])

        # Hex view
        preview = record.get("payload_preview", "")
        if preview:
            clean_hex = str(preview).replace("...", "").strip()
            try:
                raw_bytes = bytes.fromhex(clean_hex)
                self.hex_view.setPlainText(format_hex_dump(raw_bytes))
            except Exception:
                self.hex_view.setPlainText(str(preview))
        else:
            self.hex_view.setPlainText("[No payload preserved in imported record]")

    def _filter_table_view(self, text: str):
        query = text.strip().lower()
        for r in range(self.table.rowCount()):
            if not query:
                self.table.setRowHidden(r, False)
                continue
            row_content = " ".join(
                self.table.item(r, c).text().lower() for c in range(self.table.columnCount()) if self.table.item(r, c)
            )
            self.table.setRowHidden(r, query not in row_content)

    def clear_capture(self):
        self.captured_packets.clear()
        self.captured_records.clear()
        self.table.setRowCount(0)
        self.detail_tree.clear()
        self.hex_view.clear()
        self.packet_count_label.setText("Packets: 0")
        self.status_label.setText("Capture cleared.")

    def open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open PCAP File", "", "PCAP Files (*.pcap *.cap);;All Files (*)")
        if not path:
            return
        try:
            self.clear_capture()
            packets = rdpcap(path)
            for pkt in packets:
                record = monitor.extract_record(len(self.captured_packets) + 1, pkt)
                self._on_packet_captured(pkt, record)
            self.status_label.setText(f"Loaded {len(packets)} frames from {os.path.basename(path)}")
        except Exception as exc:
            QMessageBox.critical(self, "Error Opening PCAP", f"Failed to load file: {exc}")

    def open_json(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import JSON File", "", "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        try:
            records = monitor.import_json(path)
            self.clear_capture()
            for r in records:
                pkt = monitor.record_to_packet(r)
                self._on_packet_captured(pkt, r)
            self.status_label.setText(f"Imported {len(records)} records from {os.path.basename(path)}")
        except Exception as exc:
            QMessageBox.critical(self, "Error Importing JSON", f"Failed to import file: {exc}")

    def open_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import CSV File", "", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return
        try:
            records = monitor.import_csv(path)
            self.clear_capture()
            for r in records:
                pkt = monitor.record_to_packet(r)
                self._on_packet_captured(pkt, r)
            self.status_label.setText(f"Imported {len(records)} records from {os.path.basename(path)}")
        except Exception as exc:
            QMessageBox.critical(self, "Error Importing CSV", f"Failed to import file: {exc}")

    def export_pcap(self):
        valid_packets = [p for p in self.captured_packets if p is not None]
        if not valid_packets:
            QMessageBox.information(self, "Export PCAP", "No packets captured or available to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export PCAP", "capture.pcap", "PCAP Files (*.pcap);;All Files (*)")
        if not path:
            return
        try:
            wrpcap(path, valid_packets)
            QMessageBox.information(self, "Export Successful", f"Saved {len(valid_packets)} frames to {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", f"Could not save PCAP: {exc}")

    def export_json_file(self):
        if not self.captured_records:
            QMessageBox.information(self, "Export JSON", "No records to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "capture.json", "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        monitor.export_json(path, self.captured_records)
        QMessageBox.information(self, "Export Successful", f"Saved {len(self.captured_records)} records to {path}")

    def export_csv_file(self):
        if not self.captured_records:
            QMessageBox.information(self, "Export CSV", "No records to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "capture.csv", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return
        monitor.export_csv(path, self.captured_records)
        QMessageBox.information(self, "Export Successful", f"Saved {len(self.captured_records)} records to {path}")

    def _show_about(self):
        QMessageBox.about(
            self,
            "About Packet Monitor",
            "<h3>Network Packet Monitoring Application</h3>"
            "<p>A lightweight, cross-platform network packet capture and frame analysis system.</p>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>Live Layer-2 & Layer-3 packet capture</li>"
            "<li>BPF syntax filtering</li>"
            "<li>Import & Export: PCAP, JSON, CSV</li>"
            "<li>Protocol dissection tree and hex viewer</li>"
            "</ul>",
        )

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(1000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = PacketMonitorGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
