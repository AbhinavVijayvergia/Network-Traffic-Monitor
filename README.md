Network Traffic Monitoring and Anomaly Detection System
Overview

This project is a Python-based network traffic monitoring and anomaly detection tool built using packet-level analysis. It captures live network packets, analyzes traffic patterns, logs structured data, and detects potential anomalies based on traffic rate thresholds.

The goal of this project is to understand how real-world network monitoring and basic intrusion detection systems operate at the packet level.

Features

Live packet sniffing using Scapy

Protocol detection (TCP, UDP, ICMP)

Source and destination port analysis

Per-source IP traffic statistics

Timestamped and structured traffic logging

Rate-based anomaly detection using a sliding time window

How It Works

Captures live packets from the network interface.

Filters and processes only IP packets.

Extracts protocol, IP addresses, and port information.

Logs packet details with timestamps to a file.

Maintains traffic statistics per source IP.

Detects abnormal traffic rates using a configurable time window and threshold.

If traffic from a source IP exceeds the defined threshold within the time window, an alert is generated.

Anomaly Detection Logic

Window Size: 10 seconds

Threshold: 80 packets per window

This approach simulates basic intrusion detection techniques such as identifying flooding or scanning behavior.

Project Structure
network-traffic-monitor/
│── main.py
│── README.md
│── logs/
│   └── traffic_log.log

Requirements

Python 3.x

Scapy library

Administrative/root privileges (required for packet sniffing)

Usage

Clone the repository:

git clone <repository-url>
cd network-traffic-monitor


Run the program:

sudo python3 main.py


Observe real-time packet output in the terminal and logs in logs/traffic_log.log.

Learning Outcomes

Gained hands-on experience with packet-level network analysis

Understood how traffic monitoring systems operate

Implemented basic intrusion detection logic

Improved understanding of networking and security fundamentals

Future Improvements

Periodic traffic summaries

Configurable thresholds via command-line arguments

Export logs to CSV for analysis

Disclaimer

This project is intended for educational and learning purposes only. It should be used on networks where you have proper authorization.
