# Packet Sniffer

A simple Python-based network packet sniffer that captures and analyzes TCP/UDP traffic on a network interface.

## Features

- Real-time TCP/UDP packet capture (IPv4 & IPv6)
- CSV logging (timestamp, src/dst IP, protocol, ports)
- Port scan detection (>9 distinct ports within 10s from the same IP)
- Suspicious port alerts (4444, 1337, 31337, 9001, 6667)
- Periodic traffic summary every 30 seconds

## Requirements

- Python 3
- Scapy (`pip install scapy`)
- Linux (uses `AF_PACKET` raw socket)

## Usage

```bash
sudo python packetSniffer.py [interface]
```

If no interface is provided, defaults to `wlp3s0f4u1`.

List available interfaces:
```bash
ip link
```

## Output

- **log.csv** — log of all captured TCP/UDP packets
- **stdout** — scan alerts, suspicious port alerts, and periodic traffic summary
