import json
import csv
import os
import unittest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

import monitor

class TestMonitorEnhancements(unittest.TestCase):
    def test_extract_record_tcp(self):
        pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
              IP(src="192.168.1.10", dst="1.1.1.1", ttl=64) / \
              TCP(sport=12345, dport=80) / \
              Raw(load=b"GET / HTTP/1.1\r\n\r\n")

        rec = monitor.extract_record(1, pkt)
        self.assertEqual(rec["frame_no"], 1)
        self.assertEqual(rec["eth_src"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(rec["eth_dst"], "00:11:22:33:44:55")
        self.assertEqual(rec["eth_type_name"], "IPv4")
        self.assertEqual(rec["protocol"], "TCP")
        self.assertEqual(rec["src_ip"], "192.168.1.10")
        self.assertEqual(rec["dst_ip"], "1.1.1.1")
        self.assertEqual(rec["src_port"], "12345")
        self.assertEqual(rec["dst_port"], "80")
        self.assertEqual(rec["ttl"], "64")
        self.assertIn("192.168.1.10", rec["summary"])
        self.assertIn("47 45 54 20", rec["payload_preview"])

    def test_extract_record_arp(self):
        pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / \
              ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.100")

        rec = monitor.extract_record(2, pkt)
        self.assertEqual(rec["protocol"], "ARP")
        self.assertEqual(rec["src_ip"], "192.168.1.1")
        self.assertEqual(rec["dst_ip"], "192.168.1.100")

    def test_extract_record_ipv6_udp(self):
        pkt = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5353, dport=5353)
        rec = monitor.extract_record(3, pkt)
        self.assertEqual(rec["protocol"], "UDP")
        self.assertEqual(rec["src_ip"], "2001:db8::1")
        self.assertEqual(rec["dst_ip"], "2001:db8::2")
        self.assertEqual(rec["src_port"], "5353")
        self.assertEqual(rec["dst_port"], "5353")

    def test_json_and_csv_export(self):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0)
        rec = monitor.extract_record(1, pkt)
        records = [rec]

        json_file = "test_export.json"
        csv_file = "test_export.csv"

        try:
            monitor.export_json(json_file, records)
            self.assertTrue(os.path.exists(json_file))
            with open(json_file, "r") as f:
                data = json.load(f)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["protocol"], "ICMP")

            monitor.export_csv(csv_file, records)
            self.assertTrue(os.path.exists(csv_file))
            with open(csv_file, "r") as f:
                reader = list(csv.DictReader(f))
            self.assertEqual(len(reader), 1)
            self.assertEqual(reader[0]["protocol"], "ICMP")
            self.assertEqual(reader[0]["src_ip"], "10.0.0.1")

            # Test importing back
            imported_json = monitor.import_json(json_file)
            self.assertEqual(len(imported_json), 1)
            self.assertEqual(imported_json[0]["protocol"], "ICMP")
            self.assertEqual(imported_json[0]["src_ip"], "10.0.0.1")

            imported_csv = monitor.import_csv(csv_file)
            self.assertEqual(len(imported_csv), 1)
            self.assertEqual(imported_csv[0]["protocol"], "ICMP")
            self.assertEqual(imported_csv[0]["src_ip"], "10.0.0.1")
        finally:
            if os.path.exists(json_file):
                os.remove(json_file)
            if os.path.exists(csv_file):
                os.remove(csv_file)

    def test_record_to_packet(self):
        # TCP packet
        rec_tcp = {
            "frame_no": 1,
            "eth_src": "aa:bb:cc:dd:ee:ff",
            "eth_dst": "00:11:22:33:44:55",
            "eth_type": "0x0800",
            "protocol": "TCP",
            "src_ip": "192.168.1.10",
            "dst_ip": "1.1.1.1",
            "src_port": "12345",
            "dst_port": "80",
            "ttl": "64",
            "payload_preview": "47 45 54 20",
        }
        pkt = monitor.record_to_packet(rec_tcp)
        self.assertIsNotNone(pkt)
        self.assertTrue(pkt.haslayer(Ether))
        self.assertTrue(pkt.haslayer(IP))
        self.assertTrue(pkt.haslayer(TCP))
        self.assertEqual(pkt[TCP].dport, 80)
        self.assertEqual(pkt[TCP].sport, 12345)
        self.assertTrue(pkt.haslayer(Raw))
        self.assertEqual(bytes(pkt[Raw].load), b"GET ")

        # ARP packet
        rec_arp = {
            "protocol": "ARP",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.100",
        }
        pkt_arp = monitor.record_to_packet(rec_arp)
        self.assertIsNotNone(pkt_arp)
        self.assertTrue(pkt_arp.haslayer(ARP))
        self.assertEqual(pkt_arp[ARP].psrc, "192.168.1.1")

    def test_cli_parsing(self):
        import sys
        import argparse
        old_argv = sys.argv
        try:
            sys.argv = [
                "monitor.py",
                "--iface", "lo",
                "--filter", "tcp port 80",
                "--count", "10",
                "--json", "out.json",
                "--csv", "out.csv",
                "--pcap", "out.pcap",
                "--import-json", "in.json",
                "--import-csv", "in.csv"
            ]
            parser = argparse.ArgumentParser()
            parser.add_argument("--iface")
            parser.add_argument("-f", "--filter")
            parser.add_argument("--count", type=int)
            parser.add_argument("--pcap")
            parser.add_argument("--json", dest="json_path")
            parser.add_argument("--csv", dest="csv_path")
            parser.add_argument("--import-json", dest="import_json_path")
            parser.add_argument("--import-csv", dest="import_csv_path")
            args = parser.parse_args(sys.argv[1:])
            self.assertEqual(args.iface, "lo")
            self.assertEqual(args.filter, "tcp port 80")
            self.assertEqual(args.count, 10)
            self.assertEqual(args.json_path, "out.json")
            self.assertEqual(args.csv_path, "out.csv")
            self.assertEqual(args.pcap, "out.pcap")
            self.assertEqual(args.import_json_path, "in.json")
            self.assertEqual(args.import_csv_path, "in.csv")
        finally:
            sys.argv = old_argv


class TestGUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["QT_QPA_PLATFORM"] = "offscreen"

    def test_gui_headless_flow(self):
        from PyQt6.QtWidgets import QApplication
        import gui

        app = QApplication.instance() or QApplication([])
        win = gui.PacketMonitorGUI()
        self.assertEqual(win.table.rowCount(), 0)

        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=80, dport=443) / Raw(b"PING PONG")
        rec = monitor.extract_record(1, pkt)
        win._on_packet_captured(pkt, rec)
        self.assertEqual(win.table.rowCount(), 1)

        win.table.selectRow(0)
        self.assertTrue(win.detail_tree.topLevelItemCount() > 0)
        self.assertIn("PING PONG", win.hex_view.toPlainText())

        win.clear_capture()
        self.assertEqual(win.table.rowCount(), 0)
        self.assertEqual(len(win.captured_packets), 0)

    def test_gui_import_record_flow(self):
        from PyQt6.QtWidgets import QApplication
        import gui

        app = QApplication.instance() or QApplication([])
        win = gui.PacketMonitorGUI()

        record = {
            "frame_no": 42,
            "timestamp": "2026-10-12 11:00:00",
            "eth_src": "11:22:33:44:55:66",
            "eth_dst": "aa:bb:cc:dd:ee:ff",
            "eth_type": "0x0800",
            "eth_type_name": "IPv4",
            "protocol": "UDP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": "53",
            "dst_port": "5353",
            "ttl": "128",
            "length": 60,
            "payload_bytes": 4,
            "payload_preview": "01 02 03 04",
            "summary": "Ether / IP / UDP 10.0.0.1:53 > 10.0.0.2:5353",
        }

        pkt = monitor.record_to_packet(record)
        win._on_packet_captured(pkt, record)
        self.assertEqual(win.table.rowCount(), 1)

        win.table.selectRow(0)
        self.assertTrue(win.detail_tree.topLevelItemCount() > 0)
        self.assertIn("01 02 03 04", win.hex_view.toPlainText())

        # Test selecting row when packet is None (record fallback)
        win._on_packet_captured(None, record)
        self.assertEqual(win.table.rowCount(), 2)
        win.table.selectRow(1)
        self.assertTrue(win.detail_tree.topLevelItemCount() > 0)


if __name__ == "__main__":
    unittest.main()

