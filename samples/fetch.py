"""Download the public sample captures (Wireshark's own test files, GPL-2.0). Works on Windows,
macOS and Linux: `python samples/fetch.py`. Same files as fetch.sh; they are not stored in git."""

import gzip
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/"
FILES = {
    "wpa-Induction.pcap": "wpa-Induction.pcap.gz",  # WPA2 join, 4-way handshake
    "wpa-eap-tls.pcap": "wpa-eap-tls.pcap.gz",      # 802.1X certificate login
    "dhcp.pcap": "dhcp.pcap",                        # DHCP on Ethernet
}

here = Path(__file__).parent
for name, remote in FILES.items():
    data = urllib.request.urlopen(BASE + remote, timeout=30).read()
    if remote.endswith(".gz"):
        data = gzip.decompress(data)
    (here / name).write_bytes(data)
    print(f"{name}: {len(data)} bytes")
