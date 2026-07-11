# Packet Sniffer — Vulnerability Detector & Port Scanning

Educational Python tool for network packet capture and analysis with detection of insecure protocols and port scanning techniques. Developed as an academic project at the University of Caxias do Sul (UCS), based on the open source project [VulnerablePackages](https://github.com/MaridianeLugaresi/VulnerablePackages).

> **Warning:** This software is intended exclusively for educational and research purposes. Only run it on networks and test environments where you have explicit authorization. The authors are not responsible for misuse.

---

## Features

### Insecure Protocol Detection (L7)
- **HTTP** — identifies payloads with sensitive fields (username, password)
- **FTP** — detects exposed email addresses in command arguments

### Port Scanning Detection (L3/L4) — new feature
- **Time Window Scan** — detects volumetric scanning: more than N unique ports per source IP within a 60-second sliding window (configurable threshold)
- **Half-Open Scan (SYN without ACK)** — tracks TCP connections initiated (SYN) that do not complete the handshake within 5 seconds
- **NULL Scan** — TCP packets with flags field equal to `0x00` (no flags active)
- **FIN Scan** — packets with FIN flag active and ACK inactive (`flags & 0x11 == 0x01`)
- **XMAS Scan** — packets with FIN + PSH + URG simultaneously active (`flags & 0x29 == 0x29`)

### Dashboard
- Interactive web interface (Dash + Plotly) with automatic refresh every 2 seconds
- Bar chart by attack/vulnerability category
- Detailed alert listing when clicking each bar (source IP, attack type, targeted ports)

---

## Requirements

- Python 3.8 or higher
- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) installed and accessible in PATH (pyshark dependency)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Bwavrita/packet-sniffer.git
cd packet-sniffer

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate          # Windows
.venv\Scripts\activate.bat      # Windows (cmd)

# 3. Install dependencies
pip install -r requirements.txt

sudo apt install tshark
```

---

## Usage

### Debug mode (recommended for testing)

Processes the `.pcapng` files included in the repository without needing root permissions.

```bash
python -m src
```

By default, `DEBUG = False` in `src/__main__.py` and the capture file configured is `PORT_SCAN_4000_PORTS.pcapng`, with a threshold of 3000 ports.

To test the full port scan file:

```python
# In src/__main__.py:
sniffer = VulnerableSniffer(path_file=PATH, port_threshold=4000, interface='wlp0s20f3')
sniffer_thread = threading.Thread(target=sniffer.run_debug, daemon=True)
```

### Live mode

Captures packets in real time. Edit `src/__main__.py`:

```python
DEBUG = False
```

Also change the network interface name (default: `wlp0s20f3`):

```python
sniffer = VulnerableSniffer(path_file=PATH, interface='eth0')
```

```bash
sudo python -m src
```

Access the dashboard at **http://localhost:8050** after starting.

---

## Project Structure

```
packet-sniffer/
├── src/
│   ├── __init__.py
│   ├── __main__.py               # Entry point; switches between live and debug mode
│   ├── models/
│   │   ├── __init__.py
│   │   ├── vulnerable_sniffer.py # Capture, L7 detection (HTTP/FTP), and L3/L4 (port scan)
│   │   └── ui.py                 # Dash/Plotly dashboard
│   └── pcap_files/
│       ├── PORT_SCAN_4000_PORTS.pcapng   # ~4000 port scan capture (quick test)
│       └── PORT_SCAN_ALL_PORTS.pcapng    # Full port scan capture
├── requirements.txt
└── README.md
```

---

## Dependencies

| Package | Version | Usage |
|---|---|---|
| pyshark | 0.6 | Packet capture and parsing via TShark |
| dash | 4.1.0 | Web dashboard framework |
| dash-bootstrap-components | 2.0.4 | Bootstrap styling for Dash |
| plotly | 6.7.0 | Interactive charts |

---

## License

This project is a fork of [VulnerablePackages](https://github.com/MaridianeLugaresi/VulnerablePackages).