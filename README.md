# Network Traffic Monitor

> A Python-based network traffic monitoring tool built using Scapy for 
> packet-level analysis. Captures live traffic, detects anomalous behavior 
> using rate-based heuristics, and logs structured data per session.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Scapy](https://img.shields.io/badge/Scapy-packet--capture-green)

---

## Why I Built This

Before building a full IDS, I needed to understand how packets are captured 
and analyzed at the lowest level. This tool was built to answer one question: 
how does a monitoring system decide what traffic is normal and what isn't? 
The sliding-window rate detection implemented here became the foundation for 
the anomaly detection logic in my Intrusion Detection System.

---

## Features

- Live packet sniffing using Scapy
- Protocol detection (TCP, UDP, ICMP)
- Source and destination port analysis
- Per-source IP traffic statistics
- Timestamped and structured traffic logging
- Rate-based anomaly detection using a sliding time window

---

## How It Works

1. Captures live packets from the active network interface
2. Filters and processes only IP packets
3. Extracts protocol, IP addresses, and port information
4. Logs packet details with timestamps to a structured log file
5. Maintains traffic statistics per source IP
6. Triggers an alert when traffic from a source IP exceeds the threshold within the time window

---

## Detection Logic

- **Window Size:** 10 seconds
- **Threshold:** 80 packets per window

If a source IP exceeds 80 packets within any 10-second window, an anomaly 
alert is generated — simulating detection of flooding or scanning behavior.

---

## Project Structure

```
network-traffic-monitor/
├── main.py
├── logs/
│   └── traffic_log.log
└── README.md
```

---

## Requirements

- Python 3.x
- Scapy
- Administrative/root privileges (required for packet sniffing)

---

## Installation & Usage

```bash
git clone https://github.com/AbhinavVijayvergia/Network-Traffic-Monitor.git
cd Network-Traffic-Monitor
pip install scapy
sudo python3 main.py
```

Logs are written to `logs/traffic_log.log` in real time.

---

## What I Learned

- How Scapy captures and dissects packets at the interface level
- How to extract protocol, IP, and port information from raw packets
- How sliding-window rate detection identifies abnormal traffic patterns
- How structured logging works for network monitoring tools
- Why threshold tuning matters — too low causes false positives, too high misses real attacks

---

## Limitations

- CLI only — no dashboard
- Single-interface monitoring
- Rate-based detection only — not signature-based
- No persistence beyond the current session log

---

## Future Improvements

- Periodic traffic summaries
- Configurable thresholds via command-line arguments
- Export logs to CSV for analysis
- Web dashboard (see Intrusion-Detection-System for the next iteration)
