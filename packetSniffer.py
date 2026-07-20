import json
import os
import socket
import csv
import argparse
import threading
import queue
import logging
import sys
import itertools
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


class _ClearLineHandler(logging.StreamHandler):
    def emit(self, record):
        sys.stderr.write("\r\033[K")
        super().emit(record)


def load_config(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "sniffer.json")
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"warning: could not load config {path}: {e}", file=sys.stderr)
        return {}


def setup_logging(config=None):
    config = config or {}
    log_cfg = config.get("logging", {})

    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    root = logging.getLogger("sniffer")
    root.setLevel(level)
    root.handlers.clear()

    if log_cfg.get("console", True):
        handler = _ClearLineHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)

    log_file = log_cfg.get("file")
    if log_file:
        max_bytes = log_cfg.get("max_bytes", 10 * 1024 * 1024)
        backup_count = log_cfg.get("backup_count", 5)
        if log_cfg.get("json_format", False):
            fmt = logging.Formatter(
                '{"time":"%(asctime)s","level":"%(levelname)s",'
                '"logger":"%(name)s","message":"%(message)s"}'
            )
        else:
            fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        handler.setFormatter(fmt)
        root.addHandler(handler)

    return root


class TrafficLogger:
    def __init__(self, log_path="log.csv", summary_interval=30):
        self.log = logging.getLogger("sniffer.TrafficLogger")
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

    def log_packet(self, timestamp, src_ip, dst_ip, protocol, src_port, dst_port):
        self.writer.writerow([timestamp, src_ip, dst_ip, protocol, src_port, dst_port])
        self.ip_counter[src_ip] += 1
        self.protocol_counter[protocol] += 1

    def try_summary(self, now):
        if now - self.last_summary < self.summary_interval:
            return
        self.log.info("=== Traffic Summary ===")
        self.log.info("%-45s %s", "Source IP", "Packets")
        self.log.info("-" * 52)

        for ip, count in sorted(
            self.ip_counter.items(), key=lambda x: x[1], reverse=True
        ):
            self.log.info("%-45s %d", ip, count)
        self.log.info("")
        for proto, count in sorted(self.protocol_counter.items()):
            self.log.info("%-45s %d", proto, count)
        self.ip_counter.clear()
        self.protocol_counter.clear()
        self.last_summary = now
        self.log.info("---")

    def close(self):
        self.file.close()


class PortScanDetector:
    def __init__(self, threshold=10, window_seconds=10):
        self.log = logging.getLogger("sniffer.PortScanDetector")
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
        self.log = logging.getLogger("sniffer.AlertManager")
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
    def __init__(self, config=None):
        self.log = logging.getLogger("sniffer.PacketSniffer")
        config = config or {}
        self.interface = config.get("interface", "wlp3s0f4u1")
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)
        )
        self.sock.bind((self.interface, 0))
        self.logger = TrafficLogger(
            log_path=config.get("log_path", "log.csv"),
            summary_interval=config.get("summary_interval_seconds", 30),
        )
        self.scan_detector = PortScanDetector(
            threshold=config.get("scan_threshold", 10),
            window_seconds=config.get("scan_window_seconds", 10),
        )
        self.alert_manager = AlertManager(
            suspicious_ports=set(
                config.get("suspicious_ports", [4444, 1337, 31337, 9001, 6667])
            ),
        )
        self.packet_queue = queue.Queue(
            maxsize=config.get("max_queue", 10000)
        )
        self.running = False
        self.packet_count = 0
        self.start_time = datetime.now()
        self._spinner = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

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

    def _capture_loop(self):
        while self.running:
            try:
                raw_data, _ = self.sock.recvfrom(65535)
            except OSError:
                break
            parsed = self._parse_packet(raw_data)
            if parsed is None:
                continue
            try:
                self.packet_queue.put((datetime.now(), parsed), timeout=1)
            except queue.Full:
                pass

    def _show_status(self):
        elapsed = max((datetime.now() - self.start_time).seconds, 1)
        rate = self.packet_count // elapsed
        spin = next(self._spinner)
        sys.stderr.write(f"\r{spin} {self.packet_count} packets | {rate} pkt/s")
        sys.stderr.flush()

    def _process_loop(self):
        while self.running:
            try:
                now, parsed = self.packet_queue.get(timeout=1)
            except queue.Empty:
                continue
            src_ip, dst_ip, protocol, src_port, dst_port = parsed

            self.logger.log_packet(
                now, src_ip, dst_ip, protocol, src_port, dst_port
            )
            self.scan_detector.record(src_ip, dst_port, now)

            is_scan, recent_ports = self.scan_detector.is_scan(src_ip, now)
            if is_scan:
                self.log.warning("alert! %s", src_ip)

            for alert in self.alert_manager.check_ports(src_ip, recent_ports):
                self.log.warning("%s", alert)

            self.packet_count += 1
            self._show_status()
            self.logger.try_summary(now)

    def run(self):
        self.running = True
        capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        capture_thread.start()
        try:
            self._process_loop()
        except KeyboardInterrupt:
            self.close()

    def close(self):
        self.running = False
        self.sock.close()
        self.logger.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet sniffer")
    parser.add_argument(
        "interface", nargs="?",
        help="Network interface to sniff (overrides config)",
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to config file (default: sniffer.json)",
    )
    args = parser.parse_args()
    config = load_config(args.config)
    setup_logging(config)

    if args.interface:
        config["interface"] = args.interface
    config.setdefault("interface", "wlp3s0f4u1")

    sniffer = PacketSniffer(config)
    sniffer.run()
