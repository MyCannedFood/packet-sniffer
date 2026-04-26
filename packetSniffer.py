import socket
import csv
from datetime import datetime, timedelta
from scapy.all import *
from scapy.layers.l2 import Ether
from collections import defaultdict

sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

interface = "wlp3s0f4u1"
sniffer_socket.bind((interface, 0))

scan_tracker = defaultdict(list) 
scan_tracked = defaultdict(set)

ip_counter = defaultdict(int)
port_counter = defaultdict(int)
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
            src_ip = ""
            dst_ip = ""
    
            protocol = ""
            src_port = ""
            dst_port = ""
    
            raw_data, addr = sniffer_socket.recvfrom(65535)
            packet = Ether(raw_data)
            
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                if packet.haslayer(TCP):
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = "TCP"
                
                elif packet.haslayer(UDP):
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = "UDP"
   
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
    
                    scan_tracker[src_ip].append((dst_port, datetime.now()))
                    ip_counter[src_ip] += 1
                    port_counter[dst_port] += 1
            
            writer.writerow([datetime.now(), 
                             src_ip, 
                             dst_ip,
                             protocol,
                             src_port,
                             dst_port])

            recent_ports = set()

            for port, time in scan_tracker[src_ip]:
                
                if datetime.now() - time < timedelta(seconds=10):
                    recent_ports.add(port)

                    if len(recent_ports) > 9:
                        print("alert!" + src_ip)

            if src_ip:
                ip_counter[src_ip] += 1 
            
            if protocol:
                protocol_counter[protocol] += 1
           
            if datetime.now() - last_summary > timedelta(seconds=30):
                for src_ip in ip_counter:
                    print(src_ip, ip_counter[src_ip])
                for protocol in protocol_counter:
                    print(protocol, protocol_counter[protocol])

                ip_counter.clear()
                protocol_counter.clear()
                last_summary = datetime.now()
            # print(packet.summary())
    
    except KeyboardInterrupt:
            sniffer_socket.close()
