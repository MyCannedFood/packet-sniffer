import socket
from scapy.all import *
from scapy.layers.l2 import Ether

sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

interface = "wlp3s0f4u1"
sniffer_socket.bind((interface, 0))

try:
    while True:
        src_ip = ""
        dst_ip = ""

        protocol = ""
        src_port = ""
        dst_port = ""

        raw_data, addr = sniffer_socket.recvfrom(65535)
        packet = Ether(raw_data)
        
        print("------------------------------------------------------------------------------")
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(f"Source IP {src_ip} destination IP {dst_ip}")
        else:
            print("This packet has no IP")
        
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = "TCP"
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = "UDP"
            print(f"Source Port {src_port} destination Port {dst_port} Protocol {protocol}")
        else:
            print("This packet has no TCP or UDP port")   
        
        # print(packet.summary())

except KeyboardInterrupt:
    sniffer_socket.close()
