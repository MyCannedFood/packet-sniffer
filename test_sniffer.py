from datetime import datetime, timedelta
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from packetSniffer import (
    PortScanDetector,
    AlertManager,
    TrafficLogger,
    PacketSniffer,
)


class TestPortScanDetector:
    def test_empty_tracker_no_scan(self):
        detector = PortScanDetector(threshold=3)
        is_scan, ports = detector.is_scan("10.0.0.1", datetime.now())
        assert is_scan is False
        assert ports == set()

    def test_below_threshold_no_scan(self):
        detector = PortScanDetector(threshold=3)
        now = datetime.now()
        for port in [80, 443]:
            detector.record("10.0.0.1", port, now)
        is_scan, _ = detector.is_scan("10.0.0.1", now)
        assert is_scan is False

    def test_at_threshold_triggers_scan(self):
        detector = PortScanDetector(threshold=3)
        now = datetime.now()
        for port in [80, 443, 8080]:
            detector.record("10.0.0.1", port, now)
        is_scan, ports = detector.is_scan("10.0.0.1", now)
        assert is_scan is True
        assert ports == {80, 443, 8080}

    def test_above_threshold_triggers_scan(self):
        detector = PortScanDetector(threshold=2)
        now = datetime.now()
        for port in [80, 443, 8080]:
            detector.record("10.0.0.1", port, now)
        is_scan, _ = detector.is_scan("10.0.0.1", now)
        assert is_scan is True

    def test_sliding_window_expires_old_ports(self):
        detector = PortScanDetector(threshold=2, window_seconds=1)
        now = datetime.now()
        detector.record("10.0.0.1", 80, now)
        detector.record("10.0.0.1", 443, now)
        is_scan, ports = detector.is_scan("10.0.0.1", now)
        assert is_scan is True

        later = now + timedelta(seconds=2)
        is_scan, _ = detector.is_scan("10.0.0.1", later)
        assert is_scan is False

    def test_multiple_ips_tracked_independently(self):
        detector = PortScanDetector(threshold=2)
        now = datetime.now()
        detector.record("10.0.0.1", 80, now)
        detector.record("10.0.0.2", 443, now)
        is_scan_1, _ = detector.is_scan("10.0.0.1", now)
        is_scan_2, _ = detector.is_scan("10.0.0.2", now)
        assert is_scan_1 is False
        assert is_scan_2 is False

        detector.record("10.0.0.1", 443, now)
        is_scan_1, _ = detector.is_scan("10.0.0.1", now)
        assert is_scan_1 is True

    def test_duplicate_ports_not_counted(self):
        detector = PortScanDetector(threshold=3)
        now = datetime.now()
        detector.record("10.0.0.1", 80, now)
        detector.record("10.0.0.1", 80, now)
        detector.record("10.0.0.1", 80, now)
        is_scan, ports = detector.is_scan("10.0.0.1", now)
        assert is_scan is False
        assert ports == {80}


class TestAlertManager:
    def test_no_suspicious_ports(self):
        manager = AlertManager(suspicious_ports={4444, 1337})
        alerts = manager.check_ports("10.0.0.1", {80, 443})
        assert alerts == []

    def test_suspicious_port_detected(self):
        manager = AlertManager(suspicious_ports={4444, 1337})
        alerts = manager.check_ports("10.0.0.1", {80, 4444})
        assert len(alerts) == 1
        assert "4444" in alerts[0]
        assert "10.0.0.1" in alerts[0]

    def test_multiple_suspicious_ports(self):
        manager = AlertManager(suspicious_ports={4444, 1337})
        alerts = manager.check_ports("10.0.0.1", {4444, 1337, 80})
        assert len(alerts) == 2

    def test_empty_recent_ports(self):
        manager = AlertManager(suspicious_ports={4444})
        alerts = manager.check_ports("10.0.0.1", set())
        assert alerts == []

    def test_default_ports(self):
        manager = AlertManager()
        alerts = manager.check_ports("10.0.0.1", {4444})
        assert len(alerts) == 1


class TestTrafficLogger:
    def test_csv_written_on_log(self, tmp_path):
        log_file = tmp_path / "test.csv"
        logger = TrafficLogger(log_path=str(log_file))
        now = datetime.now()
        logger.log_packet(now, "10.0.0.1", "10.0.0.2", "TCP", 80, 443)
        logger.close()

        lines = open(log_file).readlines()
        assert len(lines) == 2
        assert "10.0.0.1" in lines[1]
        assert "TCP" in lines[1]

    def test_csv_header(self, tmp_path):
        log_file = tmp_path / "test.csv"
        logger = TrafficLogger(log_path=str(log_file))
        logger.close()

        header = open(log_file).readline().strip()
        assert "timestamp" in header
        assert "src_IP" in header
        assert "dst_IP" in header

    def test_summary_resets_counters(self, tmp_path):
        import io
        import logging

        logger = TrafficLogger(log_path=str(tmp_path / "test.csv"), summary_interval=0)
        logger.log = logging.getLogger("test")
        logger.log.addHandler(logging.StreamHandler(io.StringIO()))

        now = datetime.now()
        logger.log_packet(now, "10.0.0.1", "10.0.0.2", "TCP", 80, 443)
        logger.try_summary(now + timedelta(seconds=1))
        assert len(logger.ip_counter) == 0
        logger.close()


class TestParsePacket:
    def test_tcp_ipv4_packet(self):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80)
        sniffer = PacketSniffer.__new__(PacketSniffer)
        result = sniffer._parse_packet(bytes(pkt))
        assert result is not None
        src_ip, dst_ip, protocol, src_port, dst_port = result
        assert src_ip == "10.0.0.1"
        assert dst_ip == "10.0.0.2"
        assert protocol == "TCP"
        assert src_port == 12345
        assert dst_port == 80

    def test_udp_ipv4_packet(self):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=12345)
        sniffer = PacketSniffer.__new__(PacketSniffer)
        result = sniffer._parse_packet(bytes(pkt))
        assert result is not None
        _, _, protocol, _, _ = result
        assert protocol == "UDP"

    def test_tcp_ipv6_packet(self):
        pkt = Ether() / IPv6(src="::1", dst="::2") / TCP(sport=12345, dport=80)
        sniffer = PacketSniffer.__new__(PacketSniffer)
        result = sniffer._parse_packet(bytes(pkt))
        assert result is not None
        src_ip, dst_ip, protocol, _, _ = result
        assert src_ip == "::1"
        assert dst_ip == "::2"
        assert protocol == "TCP"

    def test_non_tcp_udp_skipped(self):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
        sniffer = PacketSniffer.__new__(PacketSniffer)
        result = sniffer._parse_packet(bytes(pkt))
        assert result is None

    def test_non_ip_skipped(self):
        pkt = Ether(type=0x0806)
        sniffer = PacketSniffer.__new__(PacketSniffer)
        result = sniffer._parse_packet(bytes(pkt))
        assert result is None
