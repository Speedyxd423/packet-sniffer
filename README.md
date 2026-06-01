# Packet Sniffer

A multithreaded packet sniffer built in Python using Scapy. Captures live network traffic, identifies protocols and services, and logs each session to a timestamped file.

## Features
- Capture TCP and UDP traffic in real time
- Identifies common services by port (HTTP, HTTPS, DNS, SSH etc.)
- Interactive filter input (tcp, udp, icmp etc.)
- Colour coded terminal output
- Logs each session to a timestamped .txt file

## Requirements
pip install scapy colorama

## Usage (enter this in terminal to run)
sudo python3 packet-sniffer.py

⚠️ For educational and authorised use only.
