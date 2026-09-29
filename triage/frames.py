"""Read a capture into a flat list of Events: only the frames that matter for a device joining.

Works on 802.11 captures (monitor mode, with or without radiotap) and on ordinary Ethernet/Wi-Fi
captures from a laptop, where only EAPOL, DHCP and DNS are visible.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

from scapy.all import BOOTP, DHCP, DNS, EAP, EAPOL, Dot11, Dot11FCS, Ether, PcapReader

MGMT = {0: "assoc_req", 1: "assoc_resp", 2: "reassoc_req", 3: "reassoc_resp", 4: "probe_req",
        5: "probe_resp", 8: "beacon", 10: "disassoc", 11: "auth", 12: "deauth"}


@dataclass
class Event:
    no: int              # frame number in the file, 1-based like Wireshark
    t: float             # seconds from the first frame
    kind: str            # auth, assoc_req, eapol, eap, dhcp, dns, deauth, data_protected, ...
    src: str
    dst: str
    bssid: str | None = None
    retry: bool = False
    info: dict = field(default_factory=dict)


@dataclass
class Capture:
    events: list[Event]
    frames: int = 0
    bad_fcs: int = 0     # frames whose checksum is wrong: corrupted in the air, ignored
    retries: int = 0     # 802.11 frames marked as a retransmission
    link: str = "none"   # "802.11" or "ethernet"


def fcs_ok(dot11: Dot11FCS) -> bool:
    raw = bytes(dot11)
    return len(raw) > 4 and struct.unpack("<I", raw[-4:])[0] == zlib.crc32(raw[:-4]) & 0xFFFFFFFF


def eapol_message(key) -> int | str:
    """Which 4-way handshake message an EAPOL-Key frame is, from its flag bits.
    msg1: ack, no MIC.  msg2: MIC, not secure.  msg3: ack + MIC + install.  msg4: MIC + secure."""
    if not getattr(key, "key_type", 1):
        return "group"
    ack, mic = key.key_ack, key.has_key_mic
    if ack and not mic:
        return 1
    if ack and mic:
        return 3
    if mic and not key.secure:
        return 2
    return 4


def _dot11_addrs(d) -> tuple[str, str, str | None]:
    """(src, dst, bssid) for any 802.11 frame, using the to/from-DS bits for data frames."""
    fc = int(d.FCfield)
    to_ds, from_ds = fc & 0x1, fc & 0x2
    if d.type == 2 and to_ds and not from_ds:
        return d.addr2, d.addr3, d.addr1
    if d.type == 2 and from_ds and not to_ds:
        return d.addr3, d.addr1, d.addr2
    return d.addr2, d.addr1, d.addr3


def _upper_layers(pkt, base: dict) -> list[Event]:
    """EAPOL, EAP, DHCP and DNS: the same on Wi-Fi and Ethernet."""
    out = []
    if pkt.haslayer(EAPOL):
        eapol = pkt[EAPOL]
        if eapol.type == 3 and eapol.payload:  # EAPOL-Key
            out.append(Event(kind="eapol", info={"msg": eapol_message(eapol.payload)}, **base))
        elif eapol.type == 1:
            out.append(Event(kind="eapol_start", **base))
    eap = next((layer for layer in pkt.iterpayloads() if isinstance(layer, EAP)), None)
    if eap is not None:  # scapy parses TLS/PEAP/... as EAP subclasses, which haslayer(EAP) misses
        out.append(Event(kind="eap", info={"code": eap.code, "type": getattr(eap, "type", None)},
                         **base))
    if pkt.haslayer(DHCP):
        opts = dict(o for o in pkt[DHCP].options if isinstance(o, tuple) and len(o) == 2)
        chaddr = ":".join(f"{b:02x}" for b in bytes(pkt[BOOTP].chaddr)[:6])
        out.append(Event(kind="dhcp", info={"type": opts.get("message-type"), "client": chaddr,
                                            "yiaddr": pkt[BOOTP].yiaddr}, **base))
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        qd = dns.qd[0] if isinstance(dns.qd, list) and dns.qd else dns.qd
        name = qd.qname.decode(errors="replace").rstrip(".") if dns.qdcount and qd else ""
        out.append(Event(kind="dns", info={"response": bool(dns.qr), "name": name,
                                           "rcode": dns.rcode, "answers": dns.ancount}, **base))
    return out


def read(path: str) -> Capture:
    cap = Capture(events=[])
    start = None
    with PcapReader(path) as reader:
        for no, pkt in enumerate(reader, 1):
            cap.frames += 1
            t = float(pkt.time)
            start = t if start is None else start
            t -= start
            if pkt.haslayer(Dot11):
                cap.link = "802.11"
                if pkt.haslayer(Dot11FCS) and not fcs_ok(pkt[Dot11FCS]):
                    cap.bad_fcs += 1
                    continue
                d = pkt[Dot11]
                if d.type == 1:  # control frames (ACK, RTS/CTS): not part of a join
                    continue
                retry = bool(int(d.FCfield) & 0x8)
                cap.retries += retry
                src, dst, bssid = _dot11_addrs(d)
                base = dict(no=no, t=t, src=src, dst=dst, bssid=bssid, retry=retry)
                if d.type == 0 and d.subtype in MGMT:
                    kind = MGMT[d.subtype]
                    info = {}
                    body = d.payload
                    if kind == "auth":
                        info = {"alg": body.algo, "seq": body.seqnum, "status": body.status}
                    elif kind in ("assoc_resp", "reassoc_resp"):
                        info = {"status": body.status}
                    elif kind in ("deauth", "disassoc"):
                        info = {"reason": body.reason}
                    elif kind in ("beacon", "probe_resp", "probe_req"):
                        info = {"ssid": _ssid(pkt)}
                    cap.events.append(Event(kind=kind, info=info, **base))
                elif d.type == 2:
                    if int(d.FCfield) & 0x40:  # protected: encrypted, contents unreadable
                        cap.events.append(Event(kind="data_protected", **base))
                    else:
                        cap.events.extend(_upper_layers(pkt, base))
            elif pkt.haslayer(Ether):
                cap.link = "ethernet" if cap.link == "none" else cap.link
                e = pkt[Ether]
                cap.events.extend(_upper_layers(pkt, dict(no=no, t=t, src=e.src, dst=e.dst)))
    return cap


def _ssid(pkt) -> str | None:
    from scapy.all import Dot11Elt

    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:
            return elt.info.decode(errors="replace")
        elt = elt.payload.getlayer(Dot11Elt)
    return None
