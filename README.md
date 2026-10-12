# Network Packet Monitoring and Ethernet Frame Analysis System

A lightweight, cross-platform packet sniffer that captures live network traffic and analyzes
**Ethernet frames** (source/destination MAC, EtherType) along with the
protocols inside them (ARP, IPv4/IPv6, TCP/UDP/ICMP). Captured frames can be filtered using
Berkeley Packet Filters (BPF) and exported to `.pcap` (Wireshark), `.json`, and `.csv` formats.

Built with Python 3 + [Scapy](https://scapy.net/). Cross-platform support across Linux, macOS, and Windows.

---

## 1. Setup

### Step 1 - Python 3
Ensure Python 3 is installed:

```bash
python --version   # or python3 --version
```

### Step 2 - Capture Drivers & Privileges

- **Linux**:
  Scapy uses native Linux PF_PACKET sockets for layer-2 capture out of the box. No extra drivers needed. Live capture requires root or raw socket capabilities:
  ```bash
  sudo python monitor.py
  ```
- **Windows**:
  Download and install [Npcap](https://npcap.com/#download). During installation, check **"Install Npcap in WinPcap API-compatible Mode"** for full layer-2 capture. Run your terminal as Administrator.
- **macOS**:
  Captures via `/dev/bpf*` devices; run using `sudo python monitor.py`.

### Step 3 - Install Dependencies
From the project folder:

```bash
pip install -r requirements.txt
```

---

## 2. Running

> **Elevated privileges are required for packet capture:**
> - On Linux / macOS: Use `sudo python monitor.py`
> - On Windows: Open Git Bash or Command Prompt as **Administrator**.

```bash
python monitor.py
```

If you do not pass `--iface`, the program lists the usable capture interfaces
and asks you to select one. The active/default adapter is marked and selected
when you press **Enter**.

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--iface NAME` | | Capture on a specific interface (skips interface picker) |
| `--filter EXPR` | `-f` | BPF filter expression (e.g. `'tcp port 80'`, `'udp'`, `'icmp'`) |
| `--count N` | | Stop capture after `N` packets (default `0` = until Ctrl+C) |
| `--pcap FILE` | | Save raw captured frames to a `.pcap` file |
| `--json FILE` | | Export parsed packet metadata and layers to a `.json` file |
| `--csv FILE` | | Export structured packet details to a `.csv` spreadsheet |

### Examples

```bash
# Capture 20 packets on active default adapter
python monitor.py --count 20

# Capture only HTTP/HTTPS traffic on eth0 or Wi-Fi
python monitor.py --iface eth0 --filter "tcp port 80 or tcp port 443"

# Capture and export to PCAP, JSON, and CSV simultaneously
python monitor.py --count 50 --pcap capture.pcap --json capture.json --csv capture.csv

# Capture only DNS queries and responses
python monitor.py --filter "udp port 53"
```

Press **Ctrl+C** to stop at any time - capture statistics and exported files are saved cleanly upon exit.

---

## 3. Understanding the Output

```
============================================================
Frame #1   [21:34:02]
Ethernet: dst=00:1a:2b:3c:4d:5e  src=aa:bb:cc:dd:ee:ff  type=0x0800 (IPv4)
   IPv4: 192.168.1.5 -> 8.8.8.8  ttl=64 proto=6 len=84
   TCP : 54321 -> 443
   Payload (24 bytes): 16 03 01 00 2C 01 00 ...
```

| Field | Meaning |
|-------|---------|
| `dst` / `src` | Destination and source **MAC addresses** of the Ethernet frame |
| `type` | EtherType - identifies the payload (0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6, 0x8100 = VLAN) |
| `IPv4/IPv6` | Network layer source/destination IP, TTL, protocol number, length |
| `TCP/UDP` | Transport layer source/destination ports |
| `ICMP` | Type and code (e.g. echo request/reply) |
| `Payload` | First 32 bytes of raw data in hexadecimal preview |

On **Ctrl+C**, a summary table is printed showing total frames and counts per protocol observed.

---

## 4. Running Tests

The test suite validates record extraction across protocols, JSON/CSV exports, and CLI argument parsing:

```bash
python -m unittest test_monitor.py
```

---

## 5. Notes and Limitations

- **Elevated Privileges**: Capturing raw network traffic requires root privileges (`sudo`) on Linux/macOS or Administrator privileges on Windows.
- **Windows Layer 2 vs Layer 3**: On Windows, Npcap provides full Ethernet layer-2 capture. Without Npcap, Scapy falls back to its layer-3 socket (IP traffic only, no Ethernet headers). On Linux, layer-2 is supported natively via PF_PACKET.
- **Wi-Fi Promiscuous Mode**: Wi-Fi adapters in managed mode capture host traffic. Capturing promiscuous traffic from other devices on the WLAN requires monitor mode.
