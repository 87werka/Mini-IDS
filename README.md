# Mini IDS (Python / Scapy)

A single-file mini Intrusion Detection System (IDS) that detects TCP traffic anomalies (e.g. SYN-scan) within a time window.

## Requirements:
- Python
- Scapy: 'pip install scapy'
- Windows:Npcap

## Run:
In one terminal (as Administrator) run: python miniIDS.py
In other terminal generate traffic e.g.: nmap  -sS 127.0.0.1

## Tunable parameters (in code):
WINDOW - time window width [s]
TRESH - threshold: number of packets from one IP in the window to trigger an alert [s]
