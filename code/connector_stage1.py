#!/usr/bin/env python3
"""
connector_stage1.py  (v2) -- the "tagger" with telemetry-corrected signatures.

WHAT CHANGED FROM v1 (and WHY)
------------------------------
The April-6 attack-window probe showed our first-cut signatures for T1190, T1620
and T1055 matched nothing, because CADETS encodes those behaviors differently:
  * exploitation leaves NO shell execve -- the implant runs inside nginx's memory;
    the real, generic signature is the web server making an OUTBOUND connection
    (a public-facing server serves, it does not dial out).
  * PROT_EXEC memory is ubiquitous (every program maps libraries executable), so
    in-memory code (T1620) is NOT independently observable.
  * the sshd injection leaves no cross-process edge (attempts failed/crashed), so
    process injection (T1055) is NOT independently observable.

So v2:
  + T1190  = a public-facing server (nginx/httpd/...) initiates an OUTBOUND
             connection to an EXTERNAL address  [the compromise signature]
  * T1071.001 = outbound connection to an EXTERNAL address (internal DNS/NTP no
             longer counted -- removes benign noise)
  * T1105  = write/create of a REAL file path, excluding /dev, logs, <unknown>
  * T1087.001 = read of an account file, excluding normal auth readers (sudo/su/
             login/sshd) which read it to authenticate, not to enumerate
  - T1620 and T1055 are NO LONGER tagged: documented as "present in the reference
             model but not observable in CADETS host telemetry" (a stated limit,
             like exfiltration which never completed).

All rules key on BEHAVIOR, not on the attacker's specific IPs/filenames; those
stay on the labeling side. Still label-independent candidate generation.

USAGE (Jupyter, FOLDER defined):
    import importlib, connector_stage1 as c1; importlib.reload(c1)
    c1.run(FOLDER, max_records=0)
"""

from __future__ import annotations
import os, glob, json, sys
from collections import Counter, defaultdict

import cadets_e3_inspect as insp   # reuse the tested reader / helpers

# ---- frozen vocab ----
WEB_SERVERS = {"nginx", "httpd", "apache", "apache2", "lighttpd"}   # public-facing
DISCOVERY_TOOLS = {
    "ps": "T1057", "lsof": "T1057", "pgrep": "T1057",
    "whoami": "T1033", "id": "T1033", "w": "T1033", "who": "T1033",
    "netstat": "T1046", "nmap": "T1046", "sockstat": "T1046",
    "ifconfig": "T1016", "arp": "T1016", "route": "T1016",
    "hostname": "T1082", "uname": "T1082",
}
ACCOUNT_FILES = {"/etc/passwd", "/etc/group", "/etc/master.passwd", "/etc/spwd.db"}
AUTH_READERS = {"sudo", "su", "login", "sshd", "getty", "passwd", "pam"}  # read pw db to authenticate
STAGE_EXCLUDE_PREFIX = ("/dev/", "/var/log/")
INTERNAL_PREFIXES = ("10.", "128.55.", "127.", "169.254.", "::1", "fe80")


# ---- tolerant field helpers ----
def _str(v):
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return v.get("string") if "string" in v else (next(iter(v.values())) if len(v) == 1 else None)
    return None


def _props(ev):
    p = ev.get("properties")
    if isinstance(p, dict) and isinstance(p.get("map"), dict):
        return p["map"]
    return {}


def _basename(path):
    return path.rsplit("/", 1)[-1] if path else None


def _is_external(ip):
    return bool(ip) and not any(ip.startswith(pre) for pre in INTERNAL_PREFIXES)


def _inputs(folder):
    return sorted(glob.glob(os.path.join(folder, "ta1-cadets-e3-official*.json.tar.gz")))


def insp_stream(inputs, max_records):
    for path in inputs:
        for st, d in insp._iter_file(path, max_records):
            if st is not None:
                yield st, d


# ---- Pass 1: lookup tables ----
def build_tables(inputs, max_records=0):
    netflow = {}
    for st, d in insp_stream(inputs, max_records):
        if st == "NetFlowObject":
            netflow[d.get("uuid")] = (d.get("remoteAddress"), d.get("remotePort"))
    return netflow


# ---- the corrected rules ----
def tag_event(et, ev, netflow):
    props = _props(ev)
    acting = props.get("exec")
    tags = []

    if et in ("EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG"):
        endp = netflow.get(insp._uuid(ev.get("predicateObject")))
        if endp and _is_external(endp[0]):
            where = "%s:%s" % (endp[0], endp[1])
            if acting in WEB_SERVERS:
                tags.append(("T1190", "%s outbound->%s" % (acting, where)))  # compromise
            tags.append(("T1071.001", "%s->%s" % (acting, where)))           # C2

    elif et == "EVENT_EXECUTE":
        newprog = _basename(_str(ev.get("predicateObjectPath")))
        if newprog in DISCOVERY_TOOLS:
            tags.append((DISCOVERY_TOOLS[newprog], newprog))

    elif et in ("EVENT_WRITE", "EVENT_CREATE_OBJECT"):
        path = _str(ev.get("predicateObjectPath"))
        if path and path != "<unknown>" and not path.startswith(STAGE_EXCLUDE_PREFIX):
            tags.append(("T1105", path))

    elif et == "EVENT_CHANGE_PRINCIPAL":
        tags.append(("PRIVCHG", acting or ""))

    elif et in ("EVENT_READ", "EVENT_OPEN"):
        path = _str(ev.get("predicateObjectPath"))
        if path in ACCOUNT_FILES and acting not in AUTH_READERS:
            tags.append(("T1087.001", "%s %s" % (acting, path)))

    elif et == "EVENT_UNLINK":
        path = _str(ev.get("predicateObjectPath"))
        if path and path != "<unknown>":
            tags.append(("T1070.004", path))

    return tags


# ---- run ----
def run(folder, max_records=0, out_name="connector_stage1_out", examples_per=4):
    inputs = _inputs(folder)
    if not inputs:
        sys.exit("No CADETS archives found in %s" % folder)
    out_dir = os.path.join(folder, out_name)
    os.makedirs(out_dir, exist_ok=True)

    sys.stderr.write("[tagger v2] pass 1/2: netflow table...\n"); sys.stderr.flush()
    netflow = build_tables(inputs, max_records)
    sys.stderr.write("[tagger v2]   netflows=%d\n" % len(netflow)); sys.stderr.flush()

    tag_counts = Counter()
    examples = defaultdict(list)
    events_seen = 0
    events_tagged = 0

    sys.stderr.write("[tagger v2] pass 2/2: tagging...\n"); sys.stderr.flush()
    for st, d in insp_stream(inputs, max_records):
        if st != "Event":
            continue
        events_seen += 1
        et = insp._enum(d.get("type"))
        tags = tag_event(et, d, netflow)
        if tags:
            events_tagged += 1
            for tech, detail in tags:
                tag_counts[tech] += 1
                if len(examples[tech]) < examples_per:
                    examples[tech].append({"event_type": et, "detail": detail,
                                           "exec": _props(d).get("exec"),
                                           "ts": d.get("timestampNanos")})
        if events_seen % 5_000_000 == 0:
            sys.stderr.write("[tagger v2]   %s events...\n" % f"{events_seen:,}"); sys.stderr.flush()

    summary = {"events_seen": events_seen, "events_tagged": events_tagged,
               "tag_counts": dict(tag_counts.most_common()),
               "examples": {k: examples[k] for k in tag_counts},
               "not_observable": ["T1620 in-memory execution", "T1055 process injection"],
               "max_records": max_records}
    with open(os.path.join(out_dir, "tagger_summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=str)

    print("Connector Stage 1 v2 (tagger) -- corrected signatures, no scoring/labels")
    print("=" * 70)
    print("events scanned : %s" % f"{events_seen:,}")
    print("events tagged  : %s  (%.2f%%)"
          % (f"{events_tagged:,}", 100 * events_tagged / max(events_seen, 1)))
    print("\nCandidate steps per technique:")
    for tech, c in tag_counts.most_common():
        print("  %-10s %s" % (tech, f"{c:,}"))
    print("\nExamples:")
    for tech in tag_counts:
        print("  == %s ==" % tech)
        for ex in examples[tech]:
            print("     %s  exec=%s  %s" % (ex["event_type"], ex["exec"], ex["detail"]))
    print("\nNOT observable in this telemetry (documented, not tagged): T1620, T1055")
    print("[tagger v2] wrote %s/tagger_summary.json" % out_dir)
    return summary


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--folder", required=True)
    ap.add_argument("--max-records", type=int, default=0)
    a = ap.parse_args()
    run(a.folder, a.max_records)
