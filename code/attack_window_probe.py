#!/usr/bin/env python3
"""
attack_window_probe.py -- look at what actually happened in ONE attack window.

Purpose: our first-cut rules for T1190 (web exploit), T1620 (in-memory code) and
T1055 (process injection) matched ZERO events, because CADETS encodes those
behaviors differently than assumed. Before writing correct generic signatures we
must SEE the real footprint. This probe reads one archive, restricts to one UTC
time window, and dumps:

  (1) which programs were active (by event volume);
  (2) every outbound network contact, split internal vs EXTERNAL, with the
      program that made it  -> reveals C2;
  (3) everything the web server (nginx) and sshd did  -> reveals exploit/injection;
  (4) the distinct memory-protection flag values on MMAP/MPROTECT  -> reveals
      whether executable-memory is recorded, and how;
  (5) MODIFY_PROCESS self vs cross-process counts  -> reveals injection encoding.

It changes nothing, scores nothing, labels nothing. It only shows structure so we
can define correct, behavior-based detection rules (keyed to behavior, not to the
specific implant names/IPs, which stay on the labeling side).

Usage (Jupyter, FOLDER defined):
    import importlib, attack_window_probe as p; importlib.reload(p)
    p.probe(FOLDER, "ta1-cadets-e3-official.json.tar.gz",
            "2018-04-06T15:15:00Z", "2018-04-06T16:10:00Z")
"""

from __future__ import annotations
import os, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

import cadets_e3_inspect as insp   # reuse tested reader/helpers

# enclave-internal network prefixes (everything else counts as external)
INTERNAL_PREFIXES = ("10.", "128.55.", "127.", "169.254.", "::1", "fe80")


def _iso_to_ns(s):
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def _ns_to_iso(ns):
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat()


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


def _is_external(ip):
    if not ip:
        return False
    return not any(ip.startswith(pre) for pre in INTERNAL_PREFIXES)


def probe(folder, archive_name, start_iso, end_iso, focus=("nginx", "sshd"),
          max_focus=60, max_external=80):
    path = os.path.join(folder, archive_name)
    if not os.path.exists(path):
        sys.exit("archive not found: %s" % path)
    start_ns, end_ns = _iso_to_ns(start_iso), _iso_to_ns(end_iso)

    # pass 1: netflow table (remote endpoints) for this archive
    sys.stderr.write("[probe] pass 1/2: netflow table...\n"); sys.stderr.flush()
    netflow = {}
    for st, d in insp._iter_file(path, 0):
        if st == "NetFlowObject":
            netflow[d.get("uuid")] = (d.get("remoteAddress"), d.get("remotePort"))
    sys.stderr.write("[probe]   netflows=%d\n" % len(netflow)); sys.stderr.flush()

    # pass 2: scan the window
    sys.stderr.write("[probe] pass 2/2: scanning window %s .. %s\n" % (start_iso, end_iso)); sys.stderr.flush()
    in_window = 0
    exec_counts = Counter()                 # exec -> event count
    exec_type = Counter()                   # (exec,type) -> count
    external = []                           # (ts,exec,ip,port)
    internal_contacts = Counter()           # (exec,ip:port) -> count
    focus_events = defaultdict(list)        # focus prog -> list of event dicts
    memflags = Counter()                    # arg_mem_flags value -> count
    memflags_examples = {}                  # value -> (exec,type)
    modproc_self = 0
    modproc_cross = 0
    modproc_cross_execs = Counter()

    for st, d in insp._iter_file(path, 0):
        if st != "Event":
            continue
        ts = d.get("timestampNanos")
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            continue
        if ts < start_ns or ts > end_ns:
            continue
        in_window += 1
        et = insp._enum(d.get("type"))
        props = _props(d)
        ex = props.get("exec")
        exec_counts[ex] += 1
        exec_type[(ex, et)] += 1

        if et in ("EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG"):
            ref = insp._uuid(d.get("predicateObject"))
            endp = netflow.get(ref)
            if endp and endp[0]:
                ip, port = endp
                if _is_external(ip):
                    if len(external) < max_external:
                        external.append((ts, ex, ip, port))
                else:
                    internal_contacts[(ex, "%s:%s" % (ip, port))] += 1

        if et in ("EVENT_MMAP", "EVENT_MPROTECT"):
            fl = props.get("arg_mem_flags")
            if fl is not None:
                memflags[fl] += 1
                memflags_examples.setdefault(fl, (ex, et))

        if et == "EVENT_MODIFY_PROCESS":
            subj = insp._uuid(d.get("subject"))
            tgt = insp._uuid(d.get("predicateObject"))
            if tgt and subj and tgt != subj:
                modproc_cross += 1
                modproc_cross_execs[ex] += 1
            else:
                modproc_self += 1

        if ex in focus and len(focus_events[ex]) < max_focus:
            focus_events[ex].append({
                "ts": _ns_to_iso(ts), "type": et,
                "pop": _str(d.get("predicateObjectPath")),
                "pop2": _str(d.get("predicateObject2Path")),
                "cmdLine": props.get("cmdLine"),
                "addr": props.get("address"),
            })

    # ---- report ----
    print("Attack-window probe  (no scoring, no labels)")
    print("=" * 60)
    print("archive : %s" % archive_name)
    print("window  : %s  ..  %s  (UTC)" % (start_iso, end_iso))
    print("events in window: %s" % f"{in_window:,}")

    print("\n(1) Most active programs in the window:")
    for ex, c in exec_counts.most_common(30):
        print("   %-18s %s" % (ex, f"{c:,}"))

    print("\n(2) EXTERNAL network contacts (non-enclave) -- candidate C2:")
    if not external:
        print("   (none)")
    for ts, ex, ip, port in external:
        print("   %s  exec=%-14s -> %s:%s" % (_ns_to_iso(ts), ex, ip, port))
    print("   internal contacts (top 15):")
    for (ex, ipp), c in internal_contacts.most_common(15):
        print("     exec=%-14s %s   x%d" % (ex, ipp, c))

    for prog in focus:
        print("\n(3) Everything '%s' did in the window (first %d):" % (prog, max_focus))
        if not focus_events.get(prog):
            print("   (no events with exec=%s)" % prog)
        for e in focus_events.get(prog, []):
            extra = " path=%s" % e["pop"] if e["pop"] else ""
            if e["pop2"]:
                extra += " path2=%s" % e["pop2"]
            if e["addr"]:
                extra += " addr=%s" % e["addr"]
            if e["cmdLine"]:
                extra += " cmd=%s" % e["cmdLine"]
            print("   %s  %-22s%s" % (e["ts"], e["type"], extra))

    print("\n(4) Memory-protection flag values seen (MMAP/MPROTECT):")
    if not memflags:
        print("   (none)")
    for fl, c in memflags.most_common(20):
        ex, et = memflags_examples[fl]
        print("   %-40s x%-7d (e.g. %s/%s)" % (str(fl)[:40], c, ex, et))

    print("\n(5) MODIFY_PROCESS:")
    print("   self (subject==target): %s" % f"{modproc_self:,}")
    print("   cross (subject!=target): %s" % f"{modproc_cross:,}")
    if modproc_cross_execs:
        print("   cross-process actors:", dict(modproc_cross_execs.most_common(10)))
    print("\n[probe] done.")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--folder", required=True)
    ap.add_argument("--archive", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    a = ap.parse_args()
    probe(a.folder, a.archive, a.start, a.end)
