"""python -m triage capture.pcap [more.pcap ...] [--json] [--device MAC]"""

from __future__ import annotations

import argparse
import json
import sys

from triage.analyze import STEPS, analyze
from triage.frames import read

MARK = {"ok": "ok  ", "failed": "FAIL", "incomplete": "... ", "not_seen": " -  "}


def text_report(path: str, cap, reports) -> str:
    lines = [f"== {path}",
             f"   {cap.frames} frames, link: {cap.link}, corrupted (bad checksum, ignored): "
             f"{cap.bad_fcs}, radio retries: {cap.retries}"]
    if not reports:
        lines.append("   No device tried to join in this capture.")
    for r in reports:
        lines.append(f"\n   Device {r.device}" + (f"  (AP {r.ap})" if r.ap else ""))
        lines.append(f"   Verdict: {r.summary}")
        for name in STEPS:
            s = r.steps[name]
            if s.status == "not_seen" and (name == "eap" or (cap.link != "802.11" and name in (
                    "authentication", "association"))):
                continue
            where = f"  [frames {s.frames[0]}-{s.frames[-1]}]" if s.frames else ""
            lines.append(f"     {MARK[s.status]} {name:<15} {s.detail}{where}")
        for d in r.disconnects:
            lines.append(f"     {d['type']} from the {d['sent_by']} at {d['time']}s "
                         f"(frame {d['frame']}): reason {d['reason']}")
        for n in r.notes:
            lines.append(f"     note: {n}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="triage", description="Which Wi-Fi join step failed, per device")
    p.add_argument("pcaps", nargs="+")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--device", help="only this device (MAC address)")
    args = p.parse_args(argv)

    out, any_failed = [], False
    for path in args.pcaps:
        cap = read(path)
        reports = analyze(cap)
        if args.device:
            reports = [r for r in reports if r.device == args.device.lower()]
        any_failed |= any(r.verdict == "stopped" for r in reports)
        if args.json:
            out.append({"file": path, "frames": cap.frames, "link": cap.link, "bad_fcs": cap.bad_fcs,
                        "retries": cap.retries, "devices": [r.to_dict() for r in reports]})
        else:
            print(text_report(path, cap, reports) + "\n")
    if args.json:
        json.dump(out, sys.stdout, indent=2)
        print()
    return 1 if any_failed else 0  # non-zero when some device failed, for CI use


if __name__ == "__main__":
    sys.exit(main())
