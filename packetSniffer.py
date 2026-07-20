import socket
import csv
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


class TrafficLogger:
    def __init__(self, log_path="log.csv", summary_interval=30):
        self.log_path = log_path
        self.summary_interval = timedelta(seconds=summary_interval)
        self.ip_counter = defaultdict(int)
        self.protocol_counter = defaultdict(int)
        self.last_summary = datetime.now()
        self.file = open(self.log_path, mode='w', newline='')
        self.writer = csv.writer(self.file)
        self.writer.writerow(
            ["timestamp", "src_IP", "dst_IP", "Protocol", "src_port", "dst_port"]
        )

    def log(self, timestamp, src_ip, dst_ip, protocol, src_port, dst_port):
        self.writer.writerow([timestamp, src_ip, dst_ip, protocol, src_port, dst_port])
        self.ip_counter[src_ip] += 1
        self.protocol_counter[protocol] += 1

    def try_summary(self, now):
        if now - self.last_summary < self.summary_interval:
            return
        print("=== Traffic Summary ===")
        for ip, count in self.ip_counter.items():
            print(ip, count)
        print("=======================")
        for proto, count in self.protocol_counter.items():
            print(proto, count)
        self.ip_counter.clear()
        self.protocol_counter.clear()
        self.last_summary = now
        print("=======================")

    def close(self):
        self.file.close()


class PortScanDetector:
    def __init__(self, threshold=10, window_seconds=10):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.scan_tracker = defaultdict(list)

    def record(self, src_ip, dst_port, now):
        self.scan_tracker[src_ip].append((dst_port, now))

    def get_recent_ports(self, src_ip, now):
        self.scan_tracker[src_ip] = [
            (p, t) for p, t in self.scan_tracker[src_ip]
            if now - t < self.window
        ]
        return {p for p, _ in self.scan_tracker[src_ip]}

    def is_scan(self, src_ip, now):
        recent = self.get_recent_ports(src_ip, now)
        return len(recent) >= self.threshold, recent


class AlertManager:
    def __init__(self, suspicious_ports=None):
        self.suspicious_ports = (
            suspicious_ports or {4444, 1337, 31337, 9001, 6667}
        )

    def check_ports(self, src_ip, recent_ports):
        return [
            f"suspicious port {port} from {src_ip}"
            for port in recent_ports
            if port in self.suspicious_ports
        ]


class PacketSniffer:
    def __init__(self, interface="wlp3s0f4u1"):
        self.interface = interface
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)
        )
        self.sock.bind((self.interface, 0))
        self.logger = TrafficLogger()
        self.scan_detector = PortScanDetector()
        self.alert_manager = AlertManager()

    def _parse_packet(self, raw_data):
        packet = Ether(raw_data)
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return None

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        else:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return None

        return src_ip, dst_ip, protocol, src_port, dst_port

    def run(self):
        try:
            while True:
                raw_data, _ = self.sock.recvfrom(65535)
                parsed = self._parse_packet(raw_data)
                if parsed is None:
                    continue

                src_ip, dst_ip, protocol, src_port, dst_port = parsed
                now = datetime.now()

                self.logger.log(now, src_ip, dst_ip, protocol, src_port, dst_port)
                self.scan_detector.record(src_ip, dst_port, now)

                is_scan, recent_ports = self.scan_detector.is_scan(src_ip, now)
                if is_scan:
                    print("alert! " + src_ip)

                for alert in self.alert_manager.check_ports(src_ip, recent_ports):
                    print(alert)

                self.logger.try_summary(now)

        except KeyboardInterrupt:
            self.close()

    def close(self):
        self.sock.close()
        self.logger.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet sniffer")
    parser.add_argument(
        "interface", nargs="?", default="wlp3s0f4u1",
        help="Network interface to sniff",
    )
    args = parser.parse_args()
    sniffer = PacketSniffer(interface=args.interface)
    sniffer.run()
