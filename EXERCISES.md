# Exercises (do these yourself; answers get graded)

## 1. Read each real capture by hand first (about 30 min)

For each file in `samples/`, open it in Wireshark before running the tool and write down:
- which device joined which AP (MAC addresses)
- the frame numbers of authentication, association, and each 4-way message
- any deauth/disassoc: who sent it, which reason code, what it means
- anything odd (corrupted frames, retries, missing steps)

Then run `python -m triage samples/<file>` and compare. Where you and the tool disagree, one
of you is wrong: find out which.

Useful Wireshark filters: `wlan.fc.type_subtype == 0x0b` (auth), `eapol`, `wlan.fc.retry == 1`,
`wlan.fcs.status == "Bad"`, `dhcp`, `dns`.

## 2. Add one feature (you write it, about 40 lines + tests)

Pick one:
- **Time to join**: milliseconds from the first authentication frame to 4-way message 4, per
  device. Where does it go in `DeviceReport`? What should it say when authentication was not
  captured?
- **Roam detection**: a device that reassociates to a *different* AP. Report "roamed from X to Y"
  and whether it was FT (auth algorithm 2) or a full re-join.
- **Probe-only devices**: count devices that only scanned (probe requests) and never tried to
  join, and list the network names they asked for.

Write the test first in `tests/test_analyze.py` using the `Seq` builder.

## 3. Capture your own (when you have a monitor-mode adapter)

Join your own home Wi-Fi with a wrong password once, then the right one, while capturing. Run the
tool. Does it name the wrong password at `key_exchange`? Save the capture (only your own network)
and add it as a real-capture test.
