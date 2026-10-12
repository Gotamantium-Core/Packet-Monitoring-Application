# Network Packet Monitoring and Ethernet Frame Analysis System

A lightweight, cross-platform packet sniffer and frame analyzer that captures live network traffic and dissects
**Ethernet frames** (MAC addresses, EtherType) along with network and transport layer protocols (ARP, IPv4/IPv6, TCP/UDP/ICMP/ICMPv6).

Supports both **CLI** (`monitor.py`) and a modern **Dark-Themed GUI** (`gui.py`) with real-time inspection, BPF capture filtering, PCAP file viewing, and exports to `.pcap` (Wireshark), `.json`, and `.csv`.

---

## 1. Features

- **Dual Interfaces**: Full-featured CLI and modern graphical desktop app (PyQt6).
- **Multi-Pane GUI Dissection**:
  - Live packet stream with protocol color badges.
  - Hierarchical layer and field inspection tree.
  - Wireshark-style 16-byte Hex & ASCII payload viewer.
  - Quick-search filter bar for instant table filtering.
  - Offline capture loader: inspect PCAP, JSON, and CSV captures without elevated privileges.
- **BPF Filtering**: Filter packets at capture time using standard Berkeley Packet Filter expressions (e.g. `tcp port 80`, `udp`, `icmp`, `icmp6`).
- **IPv6-Aware Decoding**: IPv6 hop limit and any ICMPv6 subtype (echo, neighbor discovery, router advertisement, ...) are decoded and labeled correctly.
- **Flexible Imports & Exports**: One-click import and export for PCAP (`.pcap`), structured JSON (`.json`), and CSV (`.csv`).
- **Cross-Platform**: Runs natively on Linux (native `PF_PACKET` sockets), Windows (Npcap), and macOS.
- **Standalone Executable**: Single-file binary compilation via PyInstaller (no Python runtime required).

---

## 2. Setup

### Step 1 - Python 3
Ensure Python 3 is installed:

```bash
python --version   # or python3 --version
```

### Step 2 - Capture Drivers & Privileges

- **Linux**: Uses native Linux PF_PACKET sockets. For live capturing, run with elevated privileges:
  ```bash
  sudo python monitor.py
  # or for GUI:
  sudo python gui.py
  ```
- **Windows**: Install [Npcap](https://npcap.com/#download) with *"WinPcap API-compatible Mode"* checked. Run terminal as Administrator.
- **macOS**: Runs via `/dev/bpf*`; execute with `sudo`.

### Step 3 - Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 3. Running

### A. Graphical Desktop App (GUI)
Launch the desktop interface:

```bash
python gui.py
```

Or build and launch the standalone binary:
```bash
./build.sh                  # Compiles to dist/packet-monitor-gui
./dist/packet-monitor-gui   # Run anywhere without Python installed
```

To install it as a system desktop application (shows up in your OS app launcher / Super key menu):
```bash
./install_desktop_launcher.sh
```

### B. Command-Line Interface (CLI)
```bash
python monitor.py
```

#### CLI Options

| Flag | Short | Description |
|------|-------|-------------|
| `--iface NAME` | | Capture on a specific interface (skips picker) |
| `--filter EXPR` | `-f` | BPF filter expression (e.g. `'tcp port 80'`, `'udp'`, `'icmp'`) |
| `--count N` | | Stop capture after `N` packets (default `0` = until Ctrl+C) |
| `--pcap FILE` | | Save raw captured frames to a `.pcap` file |
| `--json FILE` | | Export parsed packet metadata to a `.json` file |
| `--csv FILE` | | Export structured packet details to a `.csv` file |
| `--import-json FILE` | | Import and inspect packet records from a `.json` file |
| `--import-csv FILE` | | Import and inspect packet records from a `.csv` file |

#### CLI Examples

```bash
# Capture 20 packets on default adapter
python monitor.py --count 20

# Filter HTTP/HTTPS traffic on eth0
python monitor.py --iface eth0 --filter "tcp port 80 or tcp port 443"

# Capture and export to PCAP, JSON, and CSV simultaneously
python monitor.py --count 50 --pcap capture.pcap --json capture.json --csv capture.csv

# Import an existing JSON or CSV capture offline and re-export to other formats
python monitor.py --import-json capture.json --csv converted.csv
python monitor.py --import-csv capture.csv --pcap converted.pcap
```

---

## 4. Building Standalone Executables

You can compile Packet Monitor into a single self-contained executable that can be copied to any laptop:

- **Linux**:
  ```bash
  ./build.sh
  ```
  Produces `dist/packet-monitor-gui`.

- **Windows**:
  ```cmd
  build.bat
  ```
  Produces `dist\packet-monitor-gui.exe`.

---

## 5. Running Tests

Run the automated test suite covering protocol decoders, JSON/CSV exports, CLI parsing, and headless GUI logic:

```bash
python -m unittest test_monitor.py
```
