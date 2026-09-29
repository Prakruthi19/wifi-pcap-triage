# wifi-pcap-triage

Give it a Wi-Fi capture (`.pcap`); it tells you, for each device, how far the join got and
the step where it stopped, in plain words.

```
$ python -m triage samples/wpa-Induction.pcap
== samples/wpa-Induction.pcap
   1093 frames, link: 802.11, corrupted (bad checksum, ignored): 13, radio retries: 35

   Device 00:0d:93:82:36:3a  (AP 00:0c:41:82:b2:55)
   Verdict: Joined the network (last step seen: key_exchange), then left on its own: 8 (the sender is leaving the network)
     ok   authentication  Open System  [frames 78-80]
     ok   association     association  [frames 82-84]
     ok   key_exchange    4-way handshake complete (messages 1-4)  [frames 87-94]
      -   dhcp
      -   dns
     disassoc from the device at 36.8s (frame 1050): reason 8 (the sender is leaving the network)
     note: 256 encrypted data frames: DHCP and DNS inside them cannot be read without the network key.
```

## The steps it checks

| Step | What happens | How it can fail (what the tool says) |
|---|---|---|
| authentication | the device knocks (Open System, WPA3 SAE, or 802.11r FT) | AP never answered; AP refused with a status code |
| association | the device asks to join | AP refused (e.g. status 17: no room for more devices) |
| eap | 802.1X login, only on enterprise networks | login rejected; device never answered |
| key_exchange | 4-way handshake, both sides prove the password | AP resent message 1 after the device answered (wrong password); device never answered; message 4 missing |
| dhcp | Discover, Offer, Request, Ack | no server answered; Nak; stopped before Ack |
| dns | name lookup | name does not exist; no answer |

It also reports disconnects (deauth/disassoc), who sent them and the reason code in words
(4 = inactivity, 15 = handshake timeout, ...). It tells a device that left on its own apart
from one that was kicked off.

## Things real captures do that a lab does not

These showed up on the first real capture and are handled:

- **Corrupted frames.** 13 of 1093 frames in `wpa-Induction.pcap` fail their checksum. They
  are counted and ignored, not read as real events.
- **Radio retries.** A frame resent because no acknowledgement came back is marked with a retry
  bit. The tool does not count those as "the AP sent message 1 again", which would look like a
  wrong password.
- **Late starts.** A sniffer often starts after the join began (`wpa-eap-tls.pcap` starts at
  the 802.1X login). The report says which steps were not recorded instead of calling them failed.
- **Encryption.** After the handshake, DHCP and DNS are encrypted. The report says so.
- **Laptop captures.** A normal capture on a laptop (no monitor mode) has no 802.11 frames at
  all, only DHCP/DNS. The tool reads those too and does not pretend to see the Wi-Fi join.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python samples/fetch.py                            # 3 public captures from real hardware (or: bash samples/fetch.sh)
python -m triage samples/*.pcap                    # add --json for machine-readable output
python -m pytest                                   # 23 tests
```

Exit code 1 means some device stopped at a step, so it can gate a CI job or a test run.

## Where the test data comes from

- `tests/test_real_captures.py`: three public captures from real hardware (Wireshark's own test
  files, downloaded by `samples/fetch.sh`, not stored here).
- `tests/test_analyze.py`: failures built frame by frame with scapy (wrong password, AP full,
  login rejected, no DHCP server, name not found, ...). Public captures of failures are rare, so
  these are made on purpose. They check the logic, not a real device's behaviour.

## Status and limits (honest)

- Built 2026-09-29. Checked against 3 real public captures; not yet run on my own captures.
- It reads what is in the file. A monitor-mode sniffer hears one channel and misses frames, so
  "not seen" means "not in this capture", not "did not happen".
- No decryption: DHCP/DNS inside WPA2/WPA3 traffic are not read (Wireshark can, with the key).
- Codes are explained for the common cases only (`triage/codes.py`); others print as a number.

Companion to [wifi-testbed](https://github.com/Prakruthi19/wifi-testbed), which creates Wi-Fi
failures on purpose in an emulated lab. This tool reads captures of failures from anywhere.
