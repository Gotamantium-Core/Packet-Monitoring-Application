"""Network Packet Monitoring and Ethernet Frame Analysis System.

Usage:
    python monitor.py                     # pick an interface interactively
    python monitor.py --iface "NAME"      # capture on a named interface
    python monitor.py --filter "tcp"      # capture only matching BPF filter
    python monitor.py --count 20          # stop after 20 packets
    python monitor.py --pcap capture.pcap # also save frames to a pcap file
    python monitor.py --json capture.json # export packet details to JSON
    python monitor.py --csv capture.csv   # export packet details to CSV
    python monitor.py --import-json file  # import and inspect records from JSON
    python monitor.py --import-csv file   # import and inspect records from CSV
"""

import argparse
import csv
import json
import os
import platform
import sys
from collections import Counter
from datetime import datetime

from scapy.all import conf, get_if_list, sniff, wrpcap
from scapy.layers import inet6 as _inet6
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

# Scapy versions differ: some expose a public ``ICMPv6`` base class, others only
# the private ``_ICMPv6``. ``haslayer`` matches exact classes, so gather every
# known base to detect any ICMPv6 subtype via ``isinstance``.
_ICMPV6_BASES = tuple(
    cls for cls in (getattr(_inet6, "ICMPv6", None), getattr(_inet6, "_ICMPv6", None)) if cls is not None
)

stats = Counter()
frame_no = 0
save_pcap = False
save_records = False
captured_packets = []
captured_records = []


def iface_ipv4(iface):
    """Return the usable IPv4 addresses of an interface (link-local excluded)."""
    ips = []
    if hasattr(iface, "ips") and isinstance(iface.ips, dict):
        ips.extend(iface.ips.get(4, []))
    elif hasattr(iface, "ip") and iface.ip:
        ips.append(iface.ip)
    return [ip for ip in ips if ip and not ip.startswith("169.254.")]


def is_usable(iface):
    """An interface is usable when it owns at least one real IPv4 address or is loopback."""
    name = getattr(iface, "name", "")
    if name == "lo" or getattr(iface, "network_name", "") == "lo":
        return True
    return bool(iface_ipv4(iface))


def list_capture_interfaces():
    """Return only interfaces that can actually be captured on across platforms."""
    by_name = {}
    for iface in conf.ifaces.values():
        net_name = getattr(iface, "network_name", None)
        if net_name:
            by_name[net_name] = iface
        name = getattr(iface, "name", None)
        if name:
            by_name[name] = iface

    entries = []
    seen = set()
    for name in get_if_list():
        iface = by_name.get(name)
        if iface is not None and iface not in seen and is_usable(iface):
            entries.append(iface)
            seen.add(iface)

    # Fallback to conf.ifaces if get_if_list() didn't match
    if not entries:
        for iface in conf.ifaces.values():
            if iface not in seen and is_usable(iface):
                entries.append(iface)
                seen.add(iface)

    return entries


def default_network_name():
    iface = conf.iface
    return getattr(iface, "network_name", getattr(iface, "name", str(iface)))


def check_privileges():
    """Check if process has appropriate privileges to capture packets."""
    current_os = platform.system()
    if current_os == "Windows":
        return True
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return True


def print_privilege_hint():
    """Display OS-specific instructions for running with elevated privileges."""
    current_os = platform.system()
    if current_os == "Windows":
        print("\nPermission denied. Run your terminal as Administrator.")
    elif current_os == "Darwin":
        print("\nPermission denied. Packet capture requires elevated privileges.")
        print("Run with: sudo python monitor.py (or grant access to /dev/bpf*)")
    else:
        print("\nPermission denied. Packet capture requires root / raw-socket privileges.")
        print("Run with: sudo python monitor.py (or set capabilities: sudo setcap cap_net_raw,cap_net_admin=eip <python_binary>)")


def pick_interface():
    entries = list_capture_interfaces()
    if not entries:
        current_os = platform.system()
        if current_os == "Windows":
            print("No usable capture interfaces found. Is Npcap installed?")
        else:
            print("No usable capture interfaces found. Check your network configuration or run with sudo.")
        sys.exit(1)

    default_name = default_network_name()
    default_index = next(
        (i for i, f in enumerate(entries, 1) if getattr(f, "network_name", getattr(f, "name", None)) == default_name),
        None,
    )

    print("Available interfaces:")
    for index, iface in enumerate(entries, start=1):
        ipv4 = ", ".join(iface_ipv4(iface)) or "-"
        label = getattr(iface, "description", None) or getattr(iface, "name", str(iface))
        marker = "  <-- default" if getattr(iface, "network_name", getattr(iface, "name", None)) == default_name else ""
        print(f"  [{index}] {label}  ({ipv4}){marker}")

    prompt = f"Select an interface number [{default_index}]: " if default_index else "Select an interface number: "
    while True:
        choice = input(prompt).strip()
        if not choice and default_index:
            chosen = entries[default_index - 1]
            return getattr(chosen, "network_name", getattr(chosen, "name", str(chosen)))
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            chosen = entries[int(choice) - 1]
            return getattr(chosen, "network_name", getattr(chosen, "name", str(chosen)))
        print("Invalid choice, try again.")


def describe_ethernet(eth):
    type_name = ETH_TYPES.get(eth.type, f"0x{eth.type:04X}")
    print(f"Ethernet: dst={eth.dst}  src={eth.src}  type=0x{eth.type:04X} ({type_name})")


def describe_arp(arp):
    op = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
    print(f"   ARP : {op}  who-has {arp.pdst} tell {arp.psrc}")


def find_icmpv6(pkt):
    """Return the ICMPv6 layer of a packet, if any (any Scapy version)."""
    layer = pkt
    while layer is not None:
        if _ICMPV6_BASES and isinstance(layer, _ICMPV6_BASES):
            return layer
        layer = getattr(layer, "payload", None)
    return None


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
        icmpv6 = find_icmpv6(pkt)
        transport = f"ICMPv6: type={icmpv6.type} code={icmpv6.code}" if icmpv6 is not None else "no TCP/UDP/ICMP"
    ttl = getattr(ip, "ttl", getattr(ip, "hlim", "?"))
    length = getattr(ip, "len", getattr(ip, "plen", "?"))
    print(f"   {version}: {ip.src} -> {ip.dst}  ttl={ttl} proto={proto} len={length}")
    print(f"   {transport}")


def describe_payload(pkt):
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw])
        preview = " ".join(f"{b:02X}" for b in data[:32])
        suffix = " ..." if len(data) > 32 else ""
        print(f"   Payload ({len(data)} bytes): {preview}{suffix}")


def extract_record(frame_index, pkt):
    """Extract structured fields for JSON/CSV exports."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    eth = pkt.getlayer(Ether)

    eth_src = eth.src if eth else ""
    eth_dst = eth.dst if eth else ""
    eth_type_hex = f"0x{eth.type:04X}" if eth else ""
    eth_type_name = ETH_TYPES.get(eth.type, "") if eth else ""

    proto_name = "Unknown"
    src_ip = ""
    dst_ip = ""
    src_port = ""
    dst_port = ""
    ttl = ""
    length = len(pkt)

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        proto_name = "ARP"
        src_ip = arp.psrc
        dst_ip = arp.pdst
    elif pkt.haslayer(IP):
        ip = pkt[IP]
        proto_name = "IPv4"
        src_ip = ip.src
        dst_ip = ip.dst
        ttl = getattr(ip, "ttl", "")
        if ip.haslayer(TCP):
            proto_name = "TCP"
            src_port = ip[TCP].sport
            dst_port = ip[TCP].dport
        elif ip.haslayer(UDP):
            proto_name = "UDP"
            src_port = ip[UDP].sport
            dst_port = ip[UDP].dport
        elif ip.haslayer(ICMP):
            proto_name = "ICMP"
    elif pkt.haslayer(IPv6):
        ipv6 = pkt[IPv6]
        proto_name = "IPv6"
        src_ip = ipv6.src
        dst_ip = ipv6.dst
        ttl = getattr(ipv6, "hlim", "")
        if ipv6.haslayer(TCP):
            proto_name = "TCP"
            src_port = ipv6[TCP].sport
            dst_port = ipv6[TCP].dport
        elif ipv6.haslayer(UDP):
            proto_name = "UDP"
            src_port = ipv6[UDP].sport
            dst_port = ipv6[UDP].dport
        elif find_icmpv6(ipv6) is not None:
            proto_name = "ICMPv6"
    elif eth:
        proto_name = eth_type_name or "Ethernet"

    payload_data = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""
    preview = " ".join(f"{b:02X}" for b in payload_data[:32])
    if len(payload_data) > 32:
        preview += " ..."

    return {
        "frame_no": frame_index,
        "timestamp": timestamp,
        "eth_src": eth_src,
        "eth_dst": eth_dst,
        "eth_type": eth_type_hex,
        "eth_type_name": eth_type_name,
        "protocol": proto_name,
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "ttl": str(ttl),
        "length": length,
        "payload_bytes": len(payload_data),
        "payload_preview": preview,
        "summary": pkt.summary(),
    }


def handle(pkt):
    global frame_no
    frame_no += 1

    if save_pcap:
        captured_packets.append(pkt)

    if save_records:
        captured_records.append(extract_record(frame_no, pkt))

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


def export_json(filepath, records):
    """Write packet records to a JSON file."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        print(f"Saved {len(records)} records to {filepath}")
    except OSError as err:
        print(f"Error saving JSON export to {filepath}: {err}", file=sys.stderr)


def export_csv(filepath, records):
    """Write packet records to a CSV file."""
    if not records:
        print(f"No records to write to {filepath}")
        return
    fieldnames = [
        "frame_no",
        "timestamp",
        "eth_src",
        "eth_dst",
        "eth_type",
        "eth_type_name",
        "protocol",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "ttl",
        "length",
        "payload_bytes",
        "payload_preview",
        "summary",
    ]
    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in records:
                writer.writerow(r)
        print(f"Saved {len(records)} records to {filepath}")
    except OSError as err:
        print(f"Error saving CSV export to {filepath}: {err}", file=sys.stderr)


def import_json(filepath):
    """Read packet records from a JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    elif isinstance(data, dict):
        return [data]
    else:
        raise ValueError(f"Invalid JSON format in {filepath}: expected a list of records")


def import_csv(filepath):
    """Read packet records from a CSV file."""
    records = []
    with open(filepath, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rec = dict(row)
            if "frame_no" in rec and rec["frame_no"].isdigit():
                rec["frame_no"] = int(rec["frame_no"])
            if "length" in rec and rec["length"].isdigit():
                rec["length"] = int(rec["length"])
            if "payload_bytes" in rec and rec["payload_bytes"].isdigit():
                rec["payload_bytes"] = int(rec["payload_bytes"])
            records.append(rec)
    return records


def record_to_packet(record):
    """Attempt to reconstruct a Scapy packet object from an exported record dictionary."""
    try:
        eth_src = record.get("eth_src") or "00:00:00:00:00:00"
        eth_dst = record.get("eth_dst") or "00:00:00:00:00:00"
        eth_type_raw = record.get("eth_type")

        eth = Ether(src=eth_src, dst=eth_dst)
        if eth_type_raw:
            try:
                eth.type = int(str(eth_type_raw), 16) if str(eth_type_raw).startswith("0x") else int(eth_type_raw)
            except Exception:
                pass

        proto = (record.get("protocol") or "").upper()
        pkt = eth

        if proto == "ARP":
            arp = ARP()
            if record.get("src_ip"):
                arp.psrc = record.get("src_ip")
            if record.get("dst_ip"):
                arp.pdst = record.get("dst_ip")
            pkt = pkt / arp
        elif "IPV6" in proto or (record.get("src_ip") and ":" in str(record.get("src_ip"))):
            ip6 = IPv6()
            if record.get("src_ip"):
                ip6.src = str(record["src_ip"])
            if record.get("dst_ip"):
                ip6.dst = str(record["dst_ip"])
            if record.get("ttl"):
                try:
                    ip6.hlim = int(record["ttl"])
                except Exception:
                    pass
            pkt = pkt / ip6
            if proto == "TCP":
                tcp = TCP()
                if record.get("src_port"):
                    try:
                        tcp.sport = int(record["src_port"])
                    except Exception:
                        pass
                if record.get("dst_port"):
                    try:
                        tcp.dport = int(record["dst_port"])
                    except Exception:
                        pass
                pkt = pkt / tcp
            elif proto == "UDP":
                udp = UDP()
                if record.get("src_port"):
                    try:
                        udp.sport = int(record["src_port"])
                    except Exception:
                        pass
                if record.get("dst_port"):
                    try:
                        udp.dport = int(record["dst_port"])
                    except Exception:
                        pass
                pkt = pkt / udp
            elif proto in ("ICMP", "ICMPV6"):
                if _ICMPV6_BASES:
                    try:
                        pkt = pkt / _ICMPV6_BASES[0]()
                    except Exception:
                        pass
        elif record.get("src_ip") or record.get("dst_ip") or proto in ("IPV4", "TCP", "UDP", "ICMP"):
            ip = IP()
            if record.get("src_ip"):
                ip.src = str(record["src_ip"])
            if record.get("dst_ip"):
                ip.dst = str(record["dst_ip"])
            if record.get("ttl"):
                try:
                    ip.ttl = int(record["ttl"])
                except Exception:
                    pass
            pkt = pkt / ip
            if proto == "TCP":
                tcp = TCP()
                if record.get("src_port"):
                    try:
                        tcp.sport = int(record["src_port"])
                    except Exception:
                        pass
                if record.get("dst_port"):
                    try:
                        tcp.dport = int(record["dst_port"])
                    except Exception:
                        pass
                pkt = pkt / tcp
            elif proto == "UDP":
                udp = UDP()
                if record.get("src_port"):
                    try:
                        udp.sport = int(record["src_port"])
                    except Exception:
                        pass
                if record.get("dst_port"):
                    try:
                        udp.dport = int(record["dst_port"])
                    except Exception:
                        pass
                pkt = pkt / udp
            elif proto == "ICMP":
                pkt = pkt / ICMP()

        preview = record.get("payload_preview")
        if preview:
            clean_hex = str(preview).replace("...", "").strip()
            if clean_hex:
                try:
                    payload_bytes = bytes.fromhex(clean_hex)
                    pkt = pkt / Raw(load=payload_bytes)
                except Exception:
                    pass

        return pkt
    except Exception:
        return None



def _l3_sniff(iface, count, bpf_filter=None):
    """Native layer-3 capture, falling back to the default interface when the
    chosen one has no valid bind address."""
    kwargs = dict(prn=handle, store=False, count=count, L2socket=conf.L3socket)
    if bpf_filter:
        kwargs["filter"] = bpf_filter
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


def start_sniff(iface, count, bpf_filter=None):
    """Sniff at layer 2, falling back to the native layer-3 socket if Npcap
    (WinPcap) is not installed on Windows."""
    kwargs = dict(iface=iface, prn=handle, store=False, count=count)
    if bpf_filter:
        kwargs["filter"] = bpf_filter
    try:
        sniff(**kwargs)
    except (RuntimeError, OSError) as exc:
        text = str(exc)
        current_os = platform.system()
        if "syntax error" in text.lower() or "bpf" in text.lower():
            raise
        if current_os == "Windows" and any(k in text for k in ("layer 2", "winpcap", "Npcap")):
            print("\nNpcap/WinPcap is not available for layer-2 (Ethernet) capture.")
            print("Falling back to the native layer-3 socket (requires Administrator).")
            print("Install Npcap from https://npcap.com for full Ethernet-frame capture.\n")
            _l3_sniff(iface, count, bpf_filter)
        else:
            raise


def main():
    parser = argparse.ArgumentParser(
        description="Network packet monitoring and Ethernet frame analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python monitor.py
  python monitor.py --iface eth0 --count 50
  python monitor.py --filter "tcp port 80 or tcp port 443"
  python monitor.py --pcap capture.pcap --json capture.json --csv capture.csv
""",
    )
    parser.add_argument("--iface", help="interface to capture on")
    parser.add_argument("-f", "--filter", help="BPF capture filter expression (e.g. 'tcp port 80', 'icmp', 'udp')")
    parser.add_argument("--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    parser.add_argument("--pcap", help="write captured frames to this .pcap file")
    parser.add_argument("--json", dest="json_path", help="export parsed packet details to a JSON file")
    parser.add_argument("--csv", dest="csv_path", help="export parsed packet details to a CSV file")
    parser.add_argument("--import-json", dest="import_json_path", help="import and inspect packet records from a JSON file")
    parser.add_argument("--import-csv", dest="import_csv_path", help="import and inspect packet records from a CSV file")
    args = parser.parse_args()

    # Offline import handling
    if args.import_json_path or args.import_csv_path:
        import_path = args.import_json_path or args.import_csv_path
        print(f"\nImporting records from: {import_path}")
        try:
            if args.import_json_path:
                records = import_json(args.import_json_path)
            else:
                records = import_csv(args.import_csv_path)
        except Exception as exc:
            print(f"Error importing file: {exc}", file=sys.stderr)
            return

        for rec in records:
            proto = rec.get("protocol", "Unknown")
            stats[proto] += 1
            pkt = record_to_packet(rec)
            if pkt:
                captured_packets.append(pkt)
            captured_records.append(rec)
            src_info = f"{rec.get('src_ip', '')}:{rec.get('src_port', '')}" if rec.get('src_port') else str(rec.get('src_ip', ''))
            dst_info = f"{rec.get('dst_ip', '')}:{rec.get('dst_port', '')}" if rec.get('dst_port') else str(rec.get('dst_ip', ''))
            print(f"#{rec.get('frame_no', '?')} [{rec.get('timestamp', '')}] {rec.get('protocol', 'Unknown'):<6} "
                  f"{src_info} -> {dst_info} | {rec.get('summary', '')}")

        print(f"\nSuccessfully imported {len(records)} records.")

        if args.pcap and captured_packets:
            try:
                wrpcap(args.pcap, captured_packets)
                print(f"Saved {len(captured_packets)} frames to {args.pcap}")
            except Exception as err:
                print(f"Error saving PCAP file {args.pcap}: {err}", file=sys.stderr)

        if args.json_path:
            export_json(args.json_path, captured_records)

        if args.csv_path:
            export_csv(args.csv_path, captured_records)

        print_stats()
        return

    current_os = platform.system()
    if not check_privileges():
        print("Note: Running without root/administrator privileges.")
        print("Live packet capture may fail unless elevated or configured with raw socket capabilities.\n")

    global save_pcap, save_records
    save_pcap = bool(args.pcap)
    save_records = bool(args.json_path or args.csv_path)

    if current_os == "Windows" and not conf.use_pcap:
        print("WARNING: Npcap not found - layer-2 capture disabled.")
        print("Install Npcap from https://npcap.com to capture full Ethernet frames.\n")

    iface = args.iface or pick_interface()
    print(f"\nCapturing on : {iface}")
    if args.filter:
        print(f"BPF Filter   : {args.filter}")
    if args.pcap:
        print(f"PCAP Export  : {args.pcap}")
    if args.json_path:
        print(f"JSON Export  : {args.json_path}")
    if args.csv_path:
        print(f"CSV Export   : {args.csv_path}")
    print("Press Ctrl+C to stop.\n")

    try:
        start_sniff(iface, args.count or 0, bpf_filter=args.filter)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print_privilege_hint()
        return
    except Exception as exc:
        exc_str = str(exc)
        if any(w in exc_str.lower() for w in ("permission", "operation not permitted")):
            print_privilege_hint()
            return
        if "syntax error" in exc_str.lower() or "filter" in exc_str.lower():
            print(f"\nFilter error: Invalid BPF filter syntax '{args.filter}'.")
            print("Examples of valid BPF filters: 'tcp', 'udp port 53', 'ip host 1.1.1.1', 'icmp'")
            return
        print(f"\nCapture failed: {exc}")
        if current_os == "Windows":
            print("Install Npcap (https://npcap.com) for layer-2 capture, or run this")
            print("script as Administrator for the native layer-3 fallback.")
        else:
            print("Ensure you have root/sudo privileges and that the specified interface is valid and up.")
        return

    # Export outputs
    if args.pcap and captured_packets:
        try:
            wrpcap(args.pcap, captured_packets)
            print(f"\nSaved {len(captured_packets)} frames to {args.pcap}")
        except Exception as err:
            print(f"Error saving PCAP file {args.pcap}: {err}", file=sys.stderr)

    if args.json_path:
        export_json(args.json_path, captured_records)

    if args.csv_path:
        export_csv(args.csv_path, captured_records)

    print_stats()


if __name__ == "__main__":
    main()
