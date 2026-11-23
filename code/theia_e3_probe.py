#!/usr/bin/env python3
"""
theia_e3_probe.py (v2) -- calibration probe for the THEIA tagger.

Reads a SMALL sample and reports exactly what the tagger needs, AND runs the
tagger over the sample so we can see techniques actually fire before committing
to a full run. Computes nothing about attacks, labels, or scores; output is small
and safe to paste back.

USAGE
  python3 theia_e3_probe.py --folder . --max-records 300000
"""

from __future__ import annotations
import argparse, glob, json, os, sys
from collections import Counter, defaultdict

import cadets_e3_inspect as insp
import connector_stage1_theia as c1t

KEY_EVENTS = ["EVENT_EXECUTE", "EVENT_CONNECT", "EVENT_SENDTO", "EVENT_WRITE",
              "EVENT_CREATE_OBJECT", "EVENT_READ", "EVENT_OPEN", "EVENT_UNLINK",
              "EVENT_CLONE", "EVENT_CHANGE_PRINCIPAL"]
EX_PER_TYPE = 2


def _prefix(ip):
    ip = c1t._str(ip)
    if not ip or not isinstance(ip, str):
        return str(ip)
    parts = ip.split(".")
    if len(parts) >= 2 and parts[0].isdigit():
        return parts[0] + "." + parts[1] + "."
    return ip[:6]


def _resolve_inputs(folder, inputs):
    if inputs:
        paths = []
        for pat in inputs:
            paths.extend(sorted(glob.glob(pat)) or ([pat] if os.path.exists(pat) else []))
        return paths
    return c1t._inputs(folder)


def run(folder, inputs, max_records, out_path):
    paths = _resolve_inputs(folder, inputs)
    if not paths:
        sys.exit("No THEIA inputs found. Use --folder with ta1-theia-e3-official* files, or --inputs.")

    sys.stderr.write("[probe] pass 1/2: netflow + subject + fileobject tables (sample)...\n"); sys.stderr.flush()
    netflow, subject_name, fileobj_path = c1t.build_tables(paths, max_records)

    datum_counts = Counter(); event_type_hist = Counter()
    ex_by_type = defaultdict(list)
    fileobj_examples = []; netflow_examples = []
    remote_prefix_hist = Counter()
    events_with_inline_exec = 0; events_total = 0
    tag_counts = Counter(); tag_examples = defaultdict(list)
    c2_external_hits = 0

    sys.stderr.write("[probe] pass 2/2: histograms + raw examples + TAGGER run (sample)...\n"); sys.stderr.flush()
    for st, d in c1t.insp_stream(paths, max_records):
        datum_counts[st] += 1
        if st == "FileObject" and len(fileobj_examples) < 3:
            fileobj_examples.append(d)
        elif st == "NetFlowObject":
            ra = d.get("remoteAddress")
            if ra not in (None, "", -1):
                remote_prefix_hist[_prefix(ra)] += 1
                if len(netflow_examples) < 3:
                    netflow_examples.append(d)
        elif st == "Event":
            events_total += 1
            et = insp._enum(d.get("type"))
            if et:
                event_type_hist[et] += 1
            if c1t._str(c1t._props(d).get("exec")):
                events_with_inline_exec += 1
            if et in ("EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG"):
                endp = netflow.get(insp._uuid(d.get("predicateObject")))
                if endp and c1t._is_external(endp[0]):
                    c2_external_hits += 1
            tags = c1t.tag_event(et, d, netflow, subject_name, fileobj_path)
            for tech, detail in tags:
                tag_counts[tech] += 1
                if len(tag_examples[tech]) < 3:
                    tag_examples[tech].append((et, c1t.acting_name(d, subject_name), detail))
            if et in KEY_EVENTS and len(ex_by_type[et]) < EX_PER_TYPE:
                ex_by_type[et].append(d)

    # ---- report ----
    L = []
    def p(s=""): L.append(s)
    p("THEIA E3 PROBE v2 -- structural calibration + tagger dry-run (no scoring, no labels)")
    p("=" * 72)
    p("Inputs: %d file(s)%s" % (len(paths), ("  (sampled %d rec/file)" % max_records) if max_records else ""))
    for q in paths: p("   " + os.path.basename(q))
    p("")
    p("Datum types: " + ", ".join("%s=%s" % (k, f"{v:,}") for k, v in datum_counts.most_common()))
    p("")
    p("RESOLUTION RATES")
    p("   Subjects named          : %s" % f"{len(subject_name):,}")
    p("   FileObject paths resolved: %s   <-- must be > 0 for staging/account rules" % f"{len(fileobj_path):,}")
    p("   events w/ inline exec    : %s  (expect ~0 on THEIA)" % f"{events_with_inline_exec:,}")
    p("   external C2 connects seen: %s" % f"{c2_external_hits:,}")
    p("")
    p("TAGGER DRY-RUN -- candidate steps per technique (on this sample):")
    if tag_counts:
        for tech, c in tag_counts.most_common():
            p("   %-10s %s" % (tech, f"{c:,}"))
        p("   examples:")
        for tech in tag_counts:
            for (et, acting, detail) in tag_examples[tech]:
                p("     %-10s %-20s acting=%-14s %s" % (tech, et, str(acting), str(detail)[:70]))
    else:
        p("   (nothing tagged in sample -- the sample is early/benign; still confirm counts look sane)")
    p("")
    p("Sample resolved file paths (first 12):")
    for i, (u, pth) in enumerate(list(fileobj_path.items())[:12]):
        p("   %s" % pth)
    p("")
    p("REMOTE-ADDRESS PREFIX histogram:")
    for k, v in remote_prefix_hist.most_common(20):
        p("   %-10s %s" % (k, f"{v:,}"))
    p("")
    p("RAW FileObject examples (confirm where the path lives):")
    for i, d in enumerate(fileobj_examples):
        p("   --- FileObject %d (resolved path = %r) ---" % (i + 1, c1t._fileobject_path(d)))
        p(_indent(json.dumps(d, indent=2, default=str), 6))
    p("")
    p("RAW NetFlowObject examples:")
    for i, d in enumerate(netflow_examples):
        p("   --- NetFlowObject %d ---" % (i + 1))
        p(_indent(json.dumps(d, indent=2, default=str), 6))
    p("")
    for et in KEY_EVENTS:
        if not ex_by_type[et]:
            continue
        p("RAW %s example:" % et)
        for d in ex_by_type[et]:
            p(_indent(json.dumps(d, indent=2, default=str), 6))
        p("")

    text = "\n".join(L)
    with open(out_path, "w") as f:
        f.write(text + "\n")
    print(text)
    print("\n[probe] wrote %s" % out_path)


def _indent(s, n):
    pad = " " * n
    return "\n".join(pad + line for line in s.splitlines())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--folder", default=None)
    ap.add_argument("--inputs", nargs="+", default=None)
    ap.add_argument("--max-records", type=int, default=300000)
    ap.add_argument("--out", default="theia_probe_report.txt")
    a = ap.parse_args()
    run(a.folder, a.inputs, a.max_records or 0, a.out)
