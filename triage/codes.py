"""Meanings of the numbers inside 802.11 frames, in plain words (IEEE 802.11-2020, tables 9-49
and 9-50). Only the codes a home or lab network commonly shows; others print as "code N"."""

REASON = {
    1: "unspecified reason",
    2: "previous authentication no longer valid",
    3: "the sender is leaving (or has left)",
    4: "disconnected for inactivity (the device went quiet too long)",
    5: "the AP cannot handle any more devices",
    6: "frame from a device that had not authenticated",
    7: "frame from a device that had not associated",
    8: "the sender is leaving the network",
    9: "device asked to associate before authenticating",
    13: "invalid element in the frame",
    14: "message integrity (MIC) failure",
    15: "4-way handshake timed out (often a wrong password)",
    16: "group key handshake timed out",
    17: "security settings in the handshake differ from what was advertised",
    23: "802.1X login failed",
    24: "cipher rejected by security policy",
}

STATUS = {
    0: "success",
    1: "unspecified failure",
    10: "cannot support all requested capabilities",
    12: "denied for a reason outside 802.11 (often an access list)",
    13: "authentication algorithm not supported",
    15: "challenge failure",
    17: "the AP cannot handle any more devices",
    30: "rejected for now, try again later",
    31: "protected management frame (PMF) policy violation",
    37: "request declined",
    40: "invalid information element",
    43: "invalid key management (AKM) choice",
    53: "invalid PMKID",
    76: "anti-clogging token required (WPA3 SAE)",
    77: "WPA3 SAE group not supported",
}

AUTH_ALG = {0: "Open System", 1: "Shared Key", 2: "Fast Transition (802.11r)", 3: "SAE (WPA3)"}

EAP_TYPE = {1: "Identity", 4: "MD5", 13: "TLS", 21: "TTLS", 25: "PEAP", 43: "FAST", 52: "PWD"}

DHCP_TYPE = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "Ack", 6: "Nak", 7: "Release"}


def meaning(table: dict[int, str], code: int | None) -> str:
    if code is None:
        return "no code"
    return f"{code} ({table.get(code, 'code ' + str(code))})"
