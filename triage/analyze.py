"""Per device: which join steps happened, which one failed, and why, in plain words.

The steps, in order:
  authentication   the device knocks: "may I talk to you?" (Open System, SAE for WPA3, or FT)
  association      the device asks to join and the AP says yes or no (with a status code)
  eap              only on 802.1X (username/password or certificate) networks: the login
  key_exchange     the 4-way handshake: both sides prove they know the password, make keys
  dhcp             the device asks for an address (Discover, Offer, Request, Ack)
  dns              the device looks up a name
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field

from triage.codes import AUTH_ALG, DHCP_TYPE, EAP_TYPE, REASON, STATUS, meaning
from triage.frames import Capture, Event

STEPS = ("authentication", "association", "eap", "key_exchange", "dhcp", "dns")
BROADCAST = "ff:ff:ff:ff:ff:ff"


@dataclass
class Step:
    status: str                 # ok, failed, incomplete, not_seen
    detail: str = ""
    frames: list[int] = field(default_factory=list)


@dataclass
class DeviceReport:
    device: str
    ap: str | None
    verdict: str                # joined, left, disconnected, stopped, unclear
    stopped_at: str | None
    summary: str
    steps: dict[str, Step]
    disconnects: list[dict]
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def access_points(events: list[Event]) -> set[str]:
    aps = {e.src for e in events if e.kind in ("beacon", "probe_resp")}
    aps |= {e.bssid for e in events if e.bssid and e.kind in ("auth", "assoc_req", "reassoc_req",
                                                                "data_protected", "eapol", "eap")}
    return aps - {None, BROADCAST}


def devices(cap: Capture) -> list[str]:
    """Devices that tried to join (or talked DHCP/DNS), in the order they first appear."""
    aps = access_points(cap.events) if cap.link == "802.11" else set()
    seen: dict[str, None] = {}
    for e in cap.events:
        cand = None
        if e.kind in ("auth", "assoc_req", "reassoc_req") and e.src not in aps:
            cand = e.src
        elif e.kind == "eapol" and e.info.get("msg") in (2, 4):
            cand = e.src
        elif e.kind == "eap" and e.info.get("code") == 2:
            cand = e.src
        elif e.kind == "dhcp":
            cand = e.info.get("client")
        elif e.kind == "dns" and not e.info.get("response"):
            cand = e.src
        if cand and cand != BROADCAST and cand not in aps:
            seen.setdefault(cand, None)
    return list(seen)


def _mine(e: Event, sta: str) -> bool:
    if e.kind == "dhcp":
        return e.info.get("client") == sta
    return sta in (e.src, e.dst)


def _auth(ev: list[Event], sta: str) -> Step:
    reqs = [e for e in ev if e.kind == "auth" and e.src == sta]
    resps = [e for e in ev if e.kind == "auth" and e.dst == sta]
    if not reqs and not resps:
        return Step("not_seen")
    alg = (reqs or resps)[0].info.get("alg")
    name = AUTH_ALG.get(alg, f"algorithm {alg}")
    frames = [e.no for e in reqs + resps]
    bad = [e for e in resps if e.info.get("status") not in (0, None)]
    if alg == 3:  # SAE: the AP must send its Confirm (sequence 2) with success
        if any(e.info.get("seq") == 2 and e.info.get("status") == 0 for e in resps):
            return Step("ok", name, frames)
    elif any(e.info.get("status") == 0 for e in resps):
        return Step("ok", name, frames)
    if bad:
        return Step("failed", f"{name}: AP refused with status {meaning(STATUS, bad[-1].info['status'])}",
                    frames)
    if not resps:
        return Step("failed", f"{name}: the AP never answered ({len(reqs)} tries)", frames)
    return Step("incomplete", f"{name}: exchange did not finish", frames)


def _assoc(ev: list[Event], sta: str) -> Step:
    reqs = [e for e in ev if e.kind in ("assoc_req", "reassoc_req") and e.src == sta]
    resps = [e for e in ev if e.kind in ("assoc_resp", "reassoc_resp") and e.dst == sta]
    if not reqs and not resps:
        return Step("not_seen")
    frames = [e.no for e in reqs + resps]
    kind = "reassociation (roam)" if any(e.kind == "reassoc_req" for e in reqs) else "association"
    if any(e.info.get("status") == 0 for e in resps):
        return Step("ok", kind, frames)
    if resps:
        return Step("failed", f"{kind}: AP refused with status {meaning(STATUS, resps[-1].info.get('status'))}",
                    frames)
    return Step("failed", f"{kind}: the AP never answered ({len(reqs)} tries)", frames)


def _eap(ev: list[Event], sta: str) -> Step:
    eap = [e for e in ev if e.kind == "eap"]
    if not eap:
        return Step("not_seen")
    frames = [e.no for e in eap]
    methods = [EAP_TYPE.get(e.info.get("type"), f"type {e.info.get('type')}") for e in eap
               if e.info.get("code") in (1, 2) and e.info.get("type") not in (None, 1)]
    method = methods[-1] if methods else "unknown method"
    if any(e.info.get("code") == 3 for e in eap):
        return Step("ok", f"802.1X login succeeded ({method})", frames)
    if any(e.info.get("code") == 4 for e in eap):
        return Step("failed", f"802.1X login rejected ({method}): wrong credentials or certificate", frames)
    if not any(e.info.get("code") == 2 and e.src == sta for e in eap):
        return Step("failed", "the device never answered the login request", frames)
    return Step("incomplete", f"802.1X login started ({method}) but no result in the capture", frames)


def _keys(ev: list[Event], sta: str) -> Step:
    keys = [e for e in ev if e.kind == "eapol" and e.info.get("msg") in (1, 2, 3, 4)]
    if not keys:
        return Step("not_seen")
    frames = [e.no for e in keys]
    msgs = Counter(e.info["msg"] for e in keys if not e.retry)
    seen = sorted({e.info["msg"] for e in keys})
    if 4 in seen and 3 in seen:
        return Step("ok", "4-way handshake complete (messages 1-4)" if 1 in seen
                    else f"4-way handshake finished (saw messages {seen})", frames)
    if 3 in seen:
        return Step("failed", "AP sent message 3, the device never confirmed with message 4", frames)
    if 2 in seen:
        if msgs[1] > 1:
            return Step("failed", f"AP resent message 1 ({msgs[1]} times) after the device answered: "
                        "the AP rejected message 2, which almost always means a wrong password", frames)
        return Step("failed", "device answered message 1, the AP never sent message 3 "
                    "(it rejected message 2: usually a wrong password)", frames)
    return Step("failed", f"AP sent message 1 ({msgs[1] or 1} times), the device never answered", frames)


def _dhcp(ev: list[Event]) -> Step:
    d = [e for e in ev if e.kind == "dhcp"]
    if not d:
        return Step("not_seen")
    frames = [e.no for e in d]
    kinds = [DHCP_TYPE.get(e.info.get("type"), str(e.info.get("type"))) for e in d]
    flow = ", ".join(dict.fromkeys(kinds))
    ack = [e for e in d if e.info.get("type") == 5]
    if ack:
        return Step("ok", f"got address {ack[-1].info.get('yiaddr')} ({flow})", frames)
    if "Nak" in kinds:
        return Step("failed", f"server refused the address request ({flow})", frames)
    if "Offer" not in kinds:
        return Step("failed", f"no DHCP server answered ({kinds.count('Discover')} Discover)", frames)
    return Step("failed", f"exchange stopped before Ack ({flow})", frames)


def _dns(ev: list[Event], sta: str) -> Step:
    q = [e for e in ev if e.kind == "dns" and not e.info.get("response") and e.src == sta]
    r = [e for e in ev if e.kind == "dns" and e.info.get("response") and e.dst == sta]
    if not q and not r:
        return Step("not_seen")
    frames = [e.no for e in q + r]
    name = (q or r)[0].info.get("name")
    if any(e.info.get("rcode") == 0 and e.info.get("answers") for e in r):
        return Step("ok", f"{name} resolved", frames)
    if any(e.info.get("rcode") == 3 for e in r):
        return Step("failed", f"{name}: name does not exist (NXDOMAIN)", frames)
    if r:
        return Step("failed", f"{name}: server answered with an error (rcode {r[-1].info.get('rcode')})", frames)
    return Step("failed", f"{name}: no answer from the DNS server", frames)


def analyze_device(cap: Capture, sta: str) -> DeviceReport:
    ev = [e for e in cap.events if _mine(e, sta)]
    steps = {"authentication": _auth(ev, sta), "association": _assoc(ev, sta), "eap": _eap(ev, sta),
             "key_exchange": _keys(ev, sta), "dhcp": _dhcp(ev), "dns": _dns(ev, sta)}
    ap = next((e.bssid for e in ev if e.bssid and e.bssid != BROADCAST), None)
    notes = []

    order = [s for s in STEPS if s != "eap" or steps["eap"].status != "not_seen"]
    seen = [s for s in order if steps[s].status != "not_seen"]
    if cap.link == "802.11" and seen and seen[0] != "authentication":
        missing = order[:order.index(seen[0])]
        notes.append(f"The capture starts in the middle of the join: {', '.join(missing)} not "
                     "recorded (the sniffer started late or was on another channel).")
    protected = [e for e in ev if e.kind == "data_protected"]
    if protected:
        notes.append(f"{len(protected)} encrypted data frames: DHCP and DNS inside them cannot be "
                     "read without the network key.")
    retries = sum(e.retry for e in ev)
    if ev and retries / len(ev) > 0.1:
        notes.append(f"{retries} of {len(ev)} frames were radio retries (sent again because no acknowledgement came back); a lot of these can mean a weak or busy channel.")

    disconnects = [{"frame": e.no, "time": round(e.t, 3), "type": e.kind,
                    "sent_by": "device" if e.src == sta else "AP",
                    "reason": meaning(REASON, e.info.get("reason"))}
                   for e in ev if e.kind in ("deauth", "disassoc")]

    failed = next((s for s in order if steps[s].status == "failed"), None)
    if failed:
        verdict, summary = "stopped", f"Stopped at {failed}: {steps[failed].detail}"
    elif cap.link != "802.11" and steps["dhcp"].status == "ok":
        # A normal laptop capture: the Wi-Fi join itself is invisible, only what came after.
        verdict, summary = "joined", "Got an address (Wi-Fi join steps are not visible in this kind of capture)"
    elif steps["key_exchange"].status == "ok" or steps["dhcp"].status == "ok":
        verdict, summary = "joined", "Joined the network"
        last = [s for s in seen if steps[s].status == "ok"][-1]
        summary += f" (last step seen: {last})"
    else:
        incomplete = next((s for s in order if steps[s].status == "incomplete"), None)
        verdict = "unclear"
        summary = (f"Not enough in the capture: {incomplete} started but did not finish"
                   if incomplete else "Not enough in the capture to judge the join")
    if disconnects and verdict == "joined":
        last = disconnects[-1]
        verdict = "disconnected"
        if last["sent_by"] == "device" and last["reason"].split()[0] in ("3", "8"):
            verdict = "left"  # the device said goodbye itself: normal, not a fault
            summary += f", then left on its own: {last['reason']}"
        else:
            summary += f", then disconnected by the {last['sent_by']}: {last['reason']}"
    elif disconnects and verdict == "stopped":
        last = disconnects[-1]
        summary += f". Then the {last['sent_by']} sent {last['type']}: {last['reason']}"
    return DeviceReport(sta, ap, verdict, failed, summary, steps, disconnects, notes)


def analyze(cap: Capture) -> list[DeviceReport]:
    return [analyze_device(cap, sta) for sta in devices(cap)]
