#!/usr/bin/env bash
# Download public captures from real hardware (Wireshark's own test files, GPL-2.0).
# They are not stored in this repo; the real-capture tests skip until you run this.
set -euo pipefail
cd "$(dirname "$0")"
BASE=https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures
curl -fsSL "$BASE/wpa-Induction.pcap.gz" | gunzip > wpa-Induction.pcap   # WPA2 join, 4-way handshake
curl -fsSL "$BASE/wpa-eap-tls.pcap.gz" | gunzip > wpa-eap-tls.pcap       # 802.1X certificate login
curl -fsSL "$BASE/dhcp.pcap" -o dhcp.pcap                                # DHCP on Ethernet
ls -l *.pcap
