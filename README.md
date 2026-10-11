# Network Packet Monitoring and Ethernet Frame Analysis System

A barebones packet sniffer that captures live network traffic and analyzes
**Ethernet frames** (source/destination MAC, EtherType) along with the
protocols inside them (ARP, IPv4/IPv6, TCP/UDP/ICMP). Captured frames can also
be written to a `.pcap` file for later analysis in Wireshark.

Built with Python 3 + [Scapy](https://scapy.net/) on Windows 11.

---

## 1. Setup

### Step 1 - Install Python 3
Download from <https://www.python.org/downloads/> and **check "Add Python to PATH"**
during installation. Verify in a new Git Bash window:

```bash
python --version
```

### Step 2 - Install Npcap (recommended for capturing)
Download from <https://npcap.com/#download> and install it. **During setup, check
"Install Npcap in WinPcap API-compatible Mode".** Npcap gives Scapy full
layer-2 capture on Windows (Ethernet headers, ARP, etc.). Without it the program
still runs by falling back to Scapy's native layer-3 socket, but only IP traffic
is captured and no Ethernet header is shown.

### Step 3 - Install dependencies
From this project folder:

```bash
pip install -r requirements.txt
```

---

## 2. Running

> **Run your terminal as Administrator.** Live packet capture on Windows needs
> elevated privileges. In Git Bash this means opening it via
> *right-click -> Run as administrator* before running the commands below.

```bash
python monitor.py
```

If you do not pass `--iface`, the program lists the usable capture interfaces
(adapter name + IPv4) and asks you to pick a number. The active/default adapter
is marked and selected when you just press **Enter**.

### Options

| Flag             | Description                                         |
|------------------|-----------------------------------------------------|
| `--iface NAME`   | Capture on this interface (skips the picker)        |
| `--count N`      | Stop after `N` packets (default `0` = until Ctrl+C) |
| `--pcap FILE`    | Save captured frames to a `.pcap` file              |

### Examples

```bash
python monitor.py --count 20
python monitor.py --iface "Wi-Fi" --count 50
python monitor.py --pcap capture.pcap
```

Press **Ctrl+C** to stop at any time - a statistics summary is printed on exit.

---

## 3. Understanding the output

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
| `ICMP` | type/code (e.g. ping) |
| `Payload` | First 32 bytes of raw data in hexadecimal |

When running without Npcap, frames arrive without an Ethernet header and are
shown as `Layer 3 frame (no Ethernet header)` with the IP details underneath.

On **Ctrl+C** a summary is printed showing counts of total frames and each
protocol observed.

---

## 4. Notes and limitations

- **Administrator rights are required.** Always start your terminal as
  Administrator or capture will fail/return nothing.
- **Npcap is recommended.** With Npcap installed you get full layer-2 capture
  (Ethernet headers, ARP, etc.). Without it, the program automatically falls back
  to Scapy's native layer-3 socket, which still captures IP traffic but exposes
  **no Ethernet header** (and still requires Administrator).
- **Ethernet headers are only visible on real Npcap-backed interfaces.** The
  loopback adapter and the layer-3 fallback may not show an Ethernet header.
- Wi-Fi adapters usually need to be in normal (managed) mode to capture your own
  traffic; capturing *all* traffic from other devices requires monitor mode.
