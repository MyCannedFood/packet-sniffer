# packetSniffer

A Python-based network packet sniffer with port scan detection, CSV logging, and structured logging.

## Features

- Real-time TCP/UDP packet capture (IPv4 & IPv6)
- CSV logging (timestamp, src/dst IP, protocol, ports)
- Port scan detection (configurable threshold / sliding window)
- Suspicious port alerts (configurable port list)
- Periodic traffic summary
- Threaded capture (reduces packet loss under load)
- Structured logging (console + rotating file, optional JSON)
- Full configuration via JSON file

## Requirements

- Python 3
- Scapy (`pip install scapy`)
- Linux (uses `AF_PACKET` raw socket)

## Usage

```bash
sudo python packetSniffer.py [interface] [--config path]
```

If no interface is provided, defaults to the value in `sniffer.json`.

```bash
# list available interfaces
ip link

# run with default config
sudo python packetSniffer.py

# specify interface (overrides config)
sudo python packetSniffer.py eth0

# use custom config
sudo python packetSniffer.py --config /path/to/sniffer.json
```

## Configuration

All settings are in `sniffer.json`:

| Key | Default | Description |
|-----|---------|-------------|
| `interface` | `wlp3s0f4u1` | Network interface to sniff |
| `suspicious_ports` | `[4444, 1337, ...]` | Ports that trigger alerts |
| `scan_threshold` | `10` | Distinct ports within window to trigger scan alert |
| `scan_window_seconds` | `10` | Sliding window for scan detection |
| `log_path` | `log.csv` | Path for packet CSV log |
| `summary_interval_seconds` | `30` | Traffic summary interval |
| `max_queue` | `10000` | Max queued packets before dropping |
| `logging.level` | `INFO` | Log level (DEBUG, INFO, WARNING) |
| `logging.console` | `true` | Log to stderr |
| `logging.file` | `sniffer.log` | Log file path (set to null to disable) |
| `logging.max_bytes` | `10485760` | Rotating log max size |
| `logging.backup_count` | `5` | Rotating log backups |
| `logging.json_format` | `false` | Output JSON lines instead of plain text |

## Output

- **log.csv** — log of all captured TCP/UDP packets
- **sniffer.log** — rotating log with alerts, summaries, and debug info (if enabled)
- **stderr** — live alerts and summaries

## Development

```bash
pip install -r requirements.txt
python -m pytest test_sniffer.py -v
```
