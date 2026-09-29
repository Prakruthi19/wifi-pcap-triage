"""Public captures from real hardware (Wireshark's own test files). Download them first:
    bash samples/fetch.sh
Tests skip when a file is missing, so CI without network still runs the unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from triage.analyze import analyze
from triage.frames import read

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(name):
    path = SAMPLES / name
    if not path.exists():
        pytest.skip(f"{name} missing: run bash samples/fetch.sh")
    cap = read(str(path))
    return cap, {r.device: r for r in analyze(cap)}


def test_wpa2_join_real_laptop():
    """wpa-Induction.pcap: one laptop joins a WPA2 network, uses it, then leaves."""
    cap, reports = load("wpa-Induction.pcap")
    assert cap.bad_fcs == 13  # real air: some frames arrive corrupted
    r = reports["00:0d:93:82:36:3a"]
    assert r.ap == "00:0c:41:82:b2:55"
    assert [r.steps[s].status for s in ("authentication", "association", "key_exchange")] == ["ok"] * 3
    assert r.verdict == "left" and r.disconnects[-1]["reason"].startswith("8")


def test_8021x_tls_login():
    """wpa-eap-tls.pcap: an 802.1X certificate login, capture started after association."""
    _, reports = load("wpa-eap-tls.pcap")
    r = reports["24:77:03:d2:5e:a8"]
    assert r.steps["eap"].status == "ok" and "TLS" in r.steps["eap"].detail
    assert r.steps["key_exchange"].status == "ok"
    assert any("middle of the join" in n for n in r.notes)


def test_dhcp_on_ethernet():
    """dhcp.pcap: a plain Ethernet capture, like one from a laptop without monitor mode."""
    cap, reports = load("dhcp.pcap")
    assert cap.link == "ethernet"
    r = reports["00:0b:82:01:fc:42"]
    assert r.steps["dhcp"].status == "ok" and "192.168.0.10" in r.steps["dhcp"].detail
