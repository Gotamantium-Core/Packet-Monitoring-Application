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

from scapy.all import get_if_list, sniff, wrpcap
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


def pick_interface():
    interfaces = get_if_list()
    if not interfaces:
        print("No capture interfaces found. Is Npcap installed?")
        sys.exit(1)

    print("Available interfaces:")
    for index, name in enumerate(interfaces, start=1):
        print(f"  [{index}] {name}")

    while True:
        choice = input("Select an interface number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1]
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

    eth = pkt.getlayer(Ether)
    if eth is None:
        stats["Non-Ethernet"] += 1
        return

    stats["Ethernet frames"] += 1
    print("=" * 60)
    print(f"Frame #{frame_no}   [{datetime.now().strftime('%H:%M:%S')}]")
    describe_ethernet(eth)

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


def main():
    parser = argparse.ArgumentParser(description="Network packet monitoring and Ethernet frame analysis.")
    parser.add_argument("--iface", help="interface to capture on")
    parser.add_argument("--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    parser.add_argument("--pcap", help="write captured frames to this .pcap file")
    args = parser.parse_args()

    iface = args.iface or pick_interface()
    print(f"\nCapturing on: {iface}")
    if args.pcap:
        print(f"Saving to: {args.pcap}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(iface=iface, prn=handle, store=False, count=args.count or 0)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\nPermission denied. Run your terminal as Administrator.")
        return

    print_stats()


if __name__ == "__main__":
    main()
