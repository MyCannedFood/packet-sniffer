import socket
import csv
import argparse
from datetime import datetime, timedelta
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from collections import defaultdict

suspicious_ports = {4444, 1337, 31337, 9001, 6667}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet sniffer")
    parser.add_argument("interface", nargs="?", default="wlp3s0f4u1",
                        help="Network interface to sniff")
    args = parser.parse_args()

    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sniffer_socket.bind((args.interface, 0))

    scan_tracker = defaultdict(list) 

    ip_counter = defaultdict(int)
    protocol_counter = defaultdict(int)
    last_summary = datetime.now()

    init_data = ["timestamp", 
                 "src_IP", 
                 "dst_IP", 
                 "Protocol", 
                 "src_port", 
                 "dst_port"] 

    with open('log.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(init_data)

        try:
            while True:
                raw_data, addr = sniffer_socket.recvfrom(65535)
                packet = Ether(raw_data)

                if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
                    continue

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
                    continue

                now = datetime.now()

                writer.writerow([now, src_ip, dst_ip, protocol, src_port, dst_port])

                scan_tracker[src_ip].append((dst_port, now))
                ip_counter[src_ip] += 1
                protocol_counter[protocol] += 1

                scan_tracker[src_ip] = [
                    (p, t) for p, t in scan_tracker[src_ip]
                    if now - t < timedelta(seconds=10)
                ]
                recent_ports = {p for p, _ in scan_tracker[src_ip]}

                if len(recent_ports) > 9:
                    print("alert! " + src_ip)

                for port in recent_ports:
                    if port in suspicious_ports:
                        print("suspicious port " + str(port) + " from " + src_ip)

                if now - last_summary > timedelta(seconds=30):
                    print("=== Traffic Summary ===")

                    for ip, count in ip_counter.items():
                        print(ip, count)

                    print("=======================")

                    for proto, count in protocol_counter.items():
                        print(proto, count)

                    ip_counter.clear()
                    protocol_counter.clear()
                    last_summary = datetime.now()

                    print("=======================")

        except KeyboardInterrupt:
                sniffer_socket.close()
