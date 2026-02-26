import argparse
import sys
import os
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw, get_if_list, DNS, DNSQR
from scapy.layers.l2 import Ether

# Terminal colors for better readability
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

def check_root():
    """Ensure the script is running with root privileges."""
    if os.getuid() != 0:
        print(f"{RED}[-] Error: System permissions denied. Please run as root (sudo).{RESET}")
        sys.exit(1)

def list_interfaces():
    """List all available network interfaces."""
    print(f"{BOLD}[*] Available Network Interfaces:{RESET}")
    interfaces = get_if_list()
    for i, face in enumerate(interfaces):
        print(f"  {i+1}. {face}")
    sys.exit(0)

def format_payload(data):
    """Formats raw payload into a hex/ascii dump style."""
    if not data:
        return ""
    
    # Simple ASCII representation
    ascii_payload = "".join([chr(b) if 32 <= b <= 126 else "." for b in data])
    # Hex representation
    hex_payload = data.hex(" ")
    
    return f"\n    {BOLD}[Payload (Hex)]:{RESET} {hex_payload[:60]}{'...' if len(hex_payload) > 60 else ''}" \
           f"\n    {BOLD}[Payload (ASCII)]:{RESET} {ascii_payload[:60]}{'...' if len(ascii_payload) > 60 else ''}"

def packet_callback(packet):
    """Callback function to process and display packet information with port and payload details."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_name = "IP"
        color = RESET
        details = ""

        if packet.haslayer(TCP):
            proto_name = "TCP"
            color = GREEN
            details = f" | Ports: {packet[TCP].sport} -> {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            color = CYAN
            details = f" | Ports: {packet[UDP].sport} -> {packet[UDP].dport}"
            # Check for DNS
            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                query = packet.getlayer(DNSQR).qname.decode()
                details += f" | {BOLD}DNS Query: {query}{RESET}{color}"
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            color = YELLOW
            details = f" | Type: {packet[ICMP].type}"

        print(f"{color}[+] {proto_name}: {src_ip} -> {dst_ip}{details}{RESET}")
        
        # Check for raw payload data
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(format_payload(payload))
    
    elif packet.haslayer(Ether):
        # Fallback for non-IP Ethernet frames (like ARP)
        print(f"[*] Layer 2: {packet.summary()}")

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Interface to sniff on (e.g., eth0, wlan0).")
    parser.add_argument("-l", "--list", action="store_true", help="List available network interfaces and exit.")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g., 'tcp', 'port 80', 'host 8.8.8.8')")
    parser.add_argument("-o", "--output", help="Save captured packets to a PCAP file for Wireshark analysis")
    
    args = parser.parse_args()

    # Handle interface listing
    if args.list:
        list_interfaces()

    # Sniffing requires raw socket access
    check_root()

    print(f"{BOLD}[*] Starting sniffer on {args.interface if args.interface else 'all interfaces'}...{RESET}")
    if args.filter:
        print(f"[*] Applying filter: {args.filter}")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        captured_packets = sniff(
            iface=args.interface,
            filter=args.filter,
            count=args.count,
            prn=packet_callback,
            store=bool(args.output)
        )
        
        if args.output and captured_packets:
            wrpcap(args.output, captured_packets)
            print(f"\n{GREEN}[*] Captured {len(captured_packets)} packets and saved to {args.output}{RESET}")
            
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Stopping sniffer...{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[- ] Error: {e}{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()





