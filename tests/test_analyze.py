"""Failure cases built frame by frame with scapy, written to a pcap, then triaged.
Real captures of failures are rare in public, so each failure is made on purpose here."""

from __future__ import annotations

import pytest
from scapy.all import (LLC, SNAP, BOOTP, DHCP, DNS, DNSQR, EAP, EAPOL, IP, UDP, Dot11, Dot11AssoReq,
                       Dot11AssoResp, Dot11Auth, Dot11Deauth, Dot11FCS, Ether, RadioTap, wrpcap)
from scapy.layers.eap import EAP_PEAP, EAP_TLS, EAPOL_KEY

from triage.analyze import analyze
from triage.frames import read

AP, STA = "02:00:00:00:00:aa", "02:00:00:00:00:01"


class Seq:
    """Builds a capture one frame at a time, 10 ms apart."""

    def __init__(self):
        self.pkts = []

    def add(self, pkt, retry=False):
        if retry:
            pkt[Dot11].FCfield |= 0x8
        pkt.time = 1000 + len(self.pkts) * 0.01
        self.pkts.append(pkt)
        return self

    def mgmt(self, subtype, src, dst, body):
        return self.add(RadioTap() / Dot11(type=0, subtype=subtype, addr1=dst, addr2=src, addr3=AP) / body)

    def auth(self, status=0, answer=True, alg=0):
        self.mgmt(11, STA, AP, Dot11Auth(algo=alg, seqnum=1, status=0))
        return self.mgmt(11, AP, STA, Dot11Auth(algo=alg, seqnum=2, status=status)) if answer else self

    def assoc(self, status=0):
        self.mgmt(0, STA, AP, Dot11AssoReq())
        return self.mgmt(1, AP, STA, Dot11AssoResp(status=status))

    def data(self, src, payload, retry=False):
        to_ap = src == STA
        d = Dot11(type=2, subtype=0, FCfield=0x1 if to_ap else 0x2,
                  addr1=AP if to_ap else STA, addr2=STA if to_ap else AP, addr3=AP)
        return self.add(RadioTap() / d / LLC() / SNAP() / payload, retry)

    def key(self, msg, retry=False):
        # (ack, mic, install, secure) per message; set every bit, scapy's defaults are not zero
        ack, mic, install, secure = {1: (1, 0, 0, 0), 2: (0, 1, 0, 0), 3: (1, 1, 1, 1), 4: (0, 1, 0, 1)}[msg]
        flags = dict(key_ack=ack, has_key_mic=mic, install=install, secure=secure)
        src = AP if msg in (1, 3) else STA
        return self.data(src, EAPOL(type=3) / EAPOL_KEY(key_type=1, **flags), retry)

    def handshake(self, upto=4):
        for m in range(1, upto + 1):
            self.key(m)
        return self

    def eap(self, code, typ=None, src=AP):
        methods = {13: EAP_TLS, 25: EAP_PEAP}  # these carry a flags byte, so need their own class
        if typ in methods:
            body = methods[typ](code=code)
        else:
            body = EAP(code=code, type=typ) if typ else EAP(code=code)
        return self.data(src, EAPOL(type=0) / body)

    def deauth(self, src, reason):
        dst = AP if src == STA else STA
        return self.mgmt(12, src, dst, Dot11Deauth(reason=reason))

    def triage(self, tmp_path):
        path = tmp_path / "c.pcap"
        wrpcap(str(path), self.pkts)
        cap = read(str(path))
        return cap, {r.device: r for r in analyze(cap)}


def dhcp_frame(msg, yiaddr="0.0.0.0"):
    return (Ether(src=STA, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) / BOOTP(chaddr=bytes.fromhex(STA.replace(":", "")), yiaddr=yiaddr) /
            DHCP(options=[("message-type", msg), "end"]))


def one(seq, tmp_path):
    _, reports = seq.triage(tmp_path)
    return reports[STA]


def test_full_join(tmp_path):
    r = one(Seq().auth().assoc().handshake(), tmp_path)
    assert r.verdict == "joined" and r.stopped_at is None
    assert [r.steps[s].status for s in ("authentication", "association", "key_exchange")] == ["ok"] * 3
    assert r.ap == AP


def test_wrong_password_ap_resends_message_1(tmp_path):
    r = one(Seq().auth().assoc().key(1).key(2).key(1).key(2).key(1).deauth(AP, 15), tmp_path)
    assert r.stopped_at == "key_exchange" and "wrong password" in r.steps["key_exchange"].detail
    assert r.disconnects[-1]["sent_by"] == "AP" and r.disconnects[-1]["reason"].startswith("15")


def test_radio_retries_are_not_resends(tmp_path):
    # Same message 1 sent twice at the radio level (retry bit) is not the AP trying again.
    r = one(Seq().auth().assoc().key(1).key(1, retry=True).key(2), tmp_path)
    assert "never sent message 3" in r.steps["key_exchange"].detail


def test_device_never_answers_message_1(tmp_path):
    r = one(Seq().auth().assoc().key(1).key(1).key(1), tmp_path)
    assert r.stopped_at == "key_exchange" and "never answered" in r.steps["key_exchange"].detail


def test_message_4_missing(tmp_path):
    r = one(Seq().auth().assoc().handshake(upto=3), tmp_path)
    assert "message 4" in r.steps["key_exchange"].detail


def test_association_refused_ap_full(tmp_path):
    r = one(Seq().auth().assoc(status=17), tmp_path)
    assert r.stopped_at == "association" and "17 (the AP cannot handle any more devices)" in r.summary


def test_auth_never_answered(tmp_path):
    r = one(Seq().auth(answer=False).auth(answer=False), tmp_path)
    assert r.stopped_at == "authentication" and "never answered (2 tries)" in r.summary


def test_sae_confirm_needed(tmp_path):
    # WPA3: success needs the AP's Confirm (sequence 2); a commit-only exchange is not done.
    seq = Seq()
    seq.mgmt(11, STA, AP, Dot11Auth(algo=3, seqnum=1, status=0))
    seq.mgmt(11, AP, STA, Dot11Auth(algo=3, seqnum=1, status=0))
    r = one(seq, tmp_path)
    assert r.steps["authentication"].status == "incomplete" and r.verdict == "unclear"


def test_eap_rejected(tmp_path):
    seq = Seq().auth().assoc().eap(1, 1).eap(2, 1, src=STA).eap(1, 25).eap(2, 25, src=STA).eap(4)
    r = one(seq, tmp_path)
    assert r.stopped_at == "eap" and "PEAP" in r.steps["eap"].detail


def test_eap_success_then_handshake(tmp_path):
    seq = Seq().auth().assoc().eap(1, 1).eap(2, 1, src=STA).eap(1, 13).eap(2, 13, src=STA).eap(3)
    r = one(seq.handshake(), tmp_path)
    assert r.verdict == "joined" and "TLS" in r.steps["eap"].detail


def test_capture_started_late(tmp_path):
    r = one(Seq().handshake(), tmp_path)
    assert r.verdict == "joined" and any("middle of the join" in n for n in r.notes)


def test_device_leaves_on_its_own(tmp_path):
    r = one(Seq().auth().assoc().handshake().deauth(STA, 3), tmp_path)
    assert r.verdict == "left"


def test_kicked_by_ap_for_inactivity(tmp_path):
    r = one(Seq().auth().assoc().handshake().deauth(AP, 4), tmp_path)
    assert r.verdict == "disconnected" and "inactivity" in r.summary


def test_bad_checksum_frames_are_ignored(tmp_path):
    seq = Seq().auth().assoc().handshake()
    good = RadioTap() / Dot11FCS(type=0, subtype=12, addr1=STA, addr2=AP, addr3=AP) / Dot11Deauth(reason=1)
    corrupt = RadioTap(bytes(good)[:-1] + bytes([bytes(good)[-1] ^ 0xFF]))  # break the checksum
    seq.add(corrupt)
    cap, reports = seq.triage(tmp_path)
    assert cap.bad_fcs == 1 and reports[STA].verdict == "joined"


def test_dhcp_no_server(tmp_path):
    seq = Seq()
    for _ in range(3):
        seq.add(dhcp_frame(1))
    r = one(seq, tmp_path)
    assert r.stopped_at == "dhcp" and "no DHCP server answered (3 Discover)" in r.summary


@pytest.mark.parametrize("msgs,expect", [((1, 2, 3, 5), "ok"), ((1, 2, 3, 6), "failed"), ((1, 2, 3), "failed")])
def test_dhcp_flows(msgs, expect, tmp_path):
    seq = Seq()
    for m in msgs:
        seq.add(dhcp_frame(m, "192.168.1.20" if m == 5 else "0.0.0.0"))
    r = one(seq, tmp_path)
    assert r.steps["dhcp"].status == expect
    if expect == "ok":
        assert "192.168.1.20" in r.steps["dhcp"].detail and r.verdict == "joined"


def test_dns_name_not_found(tmp_path):
    q = Ether(src=STA, dst=AP) / IP() / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="printer.lan"))
    a = Ether(src=AP, dst=STA) / IP() / UDP(sport=53, dport=5353) / DNS(qr=1, rcode=3, qd=DNSQR(qname="printer.lan"))
    r = one(Seq().add(q).add(a), tmp_path)
    assert r.stopped_at == "dns" and "NXDOMAIN" in r.summary


def test_two_devices_reported_separately(tmp_path):
    other = "02:00:00:00:00:02"
    seq = Seq().auth().assoc().handshake()
    seq.mgmt(11, other, AP, Dot11Auth(algo=0, seqnum=1, status=0))
    seq.mgmt(11, AP, other, Dot11Auth(algo=0, seqnum=2, status=12))
    _, reports = seq.triage(tmp_path)
    assert reports[STA].verdict == "joined" and reports[other].stopped_at == "authentication"
    assert AP not in reports
