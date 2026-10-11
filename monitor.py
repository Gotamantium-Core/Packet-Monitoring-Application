"""Network Packet Monitoring and Ethernet Frame Analysis System.

Usage:
    python monitor.py                     # pick an interface interactively
    python monitor.py --iface "NAME"      # capture on a named interface
    python monitor.py --count 20          # stop after 20 packets
    python monitor.py --pcap capture.pcap # also save frames to a pcap file
"""

import argparse
import sys
from collections import Counter
from datetime import datetime

from scapy.all import conf, get_if_list, sniff, wrpcap
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

ETH_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
}

stats = Counter()
frame_no = 0
save_packets = False
captured = []


def iface_ipv4(iface):
    """Return the usable IPv4 addresses of an interface (link-local excluded)."""
    return [ip for ip in iface.ips[4] if ip and not ip.startswith("169.254.")]


def is_usable(iface):
    """An interface is usable when it owns at least one real IPv4 address."""
    return bool(iface_ipv4(iface))


def list_capture_interfaces():
    """Return only interfaces that can actually be captured on, preserving the
    order used by ``get_if_list()``."""
    by_name = {iface.network_name: iface for iface in conf.ifaces.values()}
    entries = []
    for name in get_if_list():
        iface = by_name.get(name)
        if iface is not None and is_usable(iface):
            entries.append(iface)
    return entries


def default_network_name():
    iface = conf.iface
    return getattr(iface, "network_name", iface)


def pick_interface():
    entries = list_capture_interfaces()
    if not entries:
        print("No usable capture interfaces found. Is Npcap installed?")
        sys.exit(1)

    default_name = default_network_name()
    default_index = next(
        (i for i, f in enumerate(entries, 1) if f.network_name == default_name),
        None,
    )

    print("Available interfaces:")
    for index, iface in enumerate(entries, start=1):
        ipv4 = ", ".join(iface_ipv4(iface)) or "-"
        label = iface.description or iface.name
        marker = "  <-- default" if iface.network_name == default_name else ""
        print(f"  [{index}] {label}  ({ipv4}){marker}")

    prompt = f"Select an interface number [{default_index}]: " if default_index else "Select an interface number: "
    while True:
        choice = input(prompt).strip()
        if not choice and default_index:
            return entries[default_index - 1].network_name
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            return entries[int(choice) - 1].network_name
        print("Invalid choice, try again.")


def describe_ethernet(eth):
    type_name = ETH_TYPES.get(eth.type, f"0x{eth.type:04X}")
    print(f"Ethernet: dst={eth.dst}  src={eth.src}  type=0x{eth.type:04X} ({type_name})")


def describe_arp(arp):
    op = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
    print(f"   ARP : {op}  who-has {arp.pdst} tell {arp.psrc}")


def describe_ip(pkt, ip):
    version = "IPv6" if isinstance(ip, IPv6) else "IPv4"
    proto = getattr(ip, "nh", getattr(ip, "proto", "?"))
    if ip.haslayer(TCP):
        transport = f"TCP : {ip[TCP].sport} -> {ip[TCP].dport}"
    elif ip.haslayer(UDP):
        transport = f"UDP : {ip[UDP].sport} -> {ip[UDP].dport}"
    elif ip.haslayer(ICMP):
        transport = f"ICMP: type={ip[ICMP].type} code={ip[ICMP].code}"
    else:
        transport = "no TCP/UDP/ICMP"
    length = getattr(ip, "len", getattr(ip, "plen", "?"))
    print(f"   {version}: {ip.src} -> {ip.dst}  ttl={ip.ttl} proto={proto} len={length}")
    print(f"   {transport}")


def describe_payload(pkt):
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw])
        preview = " ".join(f"{b:02X}" for b in data[:32])
        suffix = " ..." if len(data) > 32 else ""
        print(f"   Payload ({len(data)} bytes): {preview}{suffix}")


def handle(pkt):
    global frame_no
    frame_no += 1

    if save_packets:
        captured.append(pkt)

    eth = pkt.getlayer(Ether)
    print("=" * 60)
    print(f"Frame #{frame_no}   [{datetime.now().strftime('%H:%M:%S')}]")

    if eth is not None:
        stats["Ethernet frames"] += 1
        describe_ethernet(eth)
    else:
        stats["Non-Ethernet"] += 1
        print(f"Layer 3 frame (no Ethernet header): {pkt.summary()}")

    if pkt.haslayer(ARP):
        stats["ARP"] += 1
        describe_arp(pkt[ARP])
    elif pkt.haslayer(IP):
        stats["IPv4"] += 1
        describe_ip(pkt, pkt[IP])
    elif pkt.haslayer(IPv6):
        stats["IPv6"] += 1
        describe_ip(pkt, pkt[IPv6])

    describe_payload(pkt)


def print_stats():
    print("\n" + "=" * 60)
    print("Capture statistics")
    print("=" * 60)
    print(f"Total frames: {frame_no}")
    for name, count in stats.most_common():
        print(f"  {name:<16} {count}")


def _l3_sniff(iface, count):
    """Native layer-3 capture, falling back to the default interface when the
    chosen one has no valid bind address."""
    kwargs = dict(prn=handle, store=False, count=count, L2socket=conf.L3socket)
    try:
        sniff(iface=iface, **kwargs)
    except (RuntimeError, OSError) as exc:
        default = default_network_name()
        text = str(exc)
        if iface != default and ("10049" in text or "not valid" in text):
            print(f"Could not bind to {iface}; using default interface {default}.")
            sniff(iface=default, **kwargs)
        else:
            raise


def start_sniff(iface, count):
    """Sniff at layer 2, falling back to the native layer-3 socket if Npcap
    (WinPcap) is not installed on Windows."""
    kwargs = dict(iface=iface, prn=handle, store=False, count=count)
    try:
        sniff(**kwargs)
    except (RuntimeError, OSError) as exc:
        text = str(exc)
        if not any(k in text for k in ("layer 2", "winpcap", "Npcap", "administrator")):
            raise
        print("\nNpcap/WinPcap is not available for layer-2 (Ethernet) capture.")
        print("Falling back to the native layer-3 socket (requires Administrator).")
        print("Install Npcap from https://npcap.com for full Ethernet-frame capture.\n")
        _l3_sniff(iface, count)


def main():
    parser = argparse.ArgumentParser(description="Network packet monitoring and Ethernet frame analysis.")
    parser.add_argument("--iface", help="interface to capture on")
    parser.add_argument("--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    parser.add_argument("--pcap", help="write captured frames to this .pcap file")
    args = parser.parse_args()

    global save_packets
    save_packets = bool(args.pcap)

    if not conf.use_pcap:
        print("WARNING: Npcap not found - layer-2 capture disabled.")
        print("Install Npcap from https://npcap.com to capture full Ethernet frames.\n")

    iface = args.iface or pick_interface()
    print(f"\nCapturing on: {iface}")
    if args.pcap:
        print(f"Saving to: {args.pcap}")
    print("Press Ctrl+C to stop.\n")

    try:
        start_sniff(iface, args.count or 0)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\nPermission denied. Run your terminal as Administrator.")
        return
    except (RuntimeError, OSError) as exc:
        print(f"\nCapture failed: {exc}")
        print("Install Npcap (https://npcap.com) for layer-2 capture, or run this")
        print("script as Administrator for the native layer-3 fallback.")
        return

    if args.pcap and captured:
        wrpcap(args.pcap, captured)
        print(f"\nSaved {len(captured)} frames to {args.pcap}")

    print_stats()


if __name__ == "__main__":
    main()
