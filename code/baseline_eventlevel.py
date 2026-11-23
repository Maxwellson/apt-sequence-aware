#!/usr/bin/env python3
"""
baseline_eventlevel.py -- the FROZEN event-level ATT&CK baseline.

This is the baseline named in the design specification: an event-level detector that
uses the SAME telemetry-to-technique mapping rules as the method, with NO sequence,
temporal, or contextual correlation and NO path aggregation. Every CDM event is an
independent alert: it fires iff the event matches any ATT&CK tagging rule
(connector_stage1.tag_event). Ground truth is the frozen event-level IOC rule from
labeling_spec.json (window + implant process / C2 IP / implant file), computed
independently of the tagger.

Because the detector is binary (fire / no-fire), the natural report is a single
operating point: precision, recall, F1, and the confusion matrix over all events.
ROC-AUC/AP are degenerate for a one-threshold detector and are not reported; the
point of this baseline is to show that event-level firing has near-zero precision,
which is what motivates path-level scoring.

USAGE (Jupyter, FOLDER defined):
    import importlib, baseline_eventlevel as b; importlib.reload(b)
    b.run(FOLDER)                      # full pass (~44M events, several minutes)
    b.run(FOLDER, max_records=2_000_000)   # quick smoke test on a prefix
"""
from __future__ import annotations
import os, sys, json
from datetime import datetime, timezone

import cadets_e3_inspect as insp
import connector_stage1 as c1


def _iso_to_ns(s):
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1e9)


def _inwin(ts, wins):
    return any(a <= ts <= b for a, b in wins)


def _basename(p):
    return p.rsplit("/", 1)[-1] if p else None


CONNECT = ("EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG")
FILEOUT = ("EVENT_WRITE", "EVENT_CREATE_OBJECT", "EVENT_UNLINK")


def run(folder, max_records=0, out_name="baseline_eventlevel_out"):
    inputs = c1._inputs(folder)
    if not inputs:
        sys.exit("No CADETS archives found in %s" % folder)
    spec = json.load(open(os.path.join(folder, "labeling_spec.json")))
    wins = [(_iso_to_ns(a), _iso_to_ns(b)) for a, b in spec["attack_windows_utc"]]
    implant = set(spec["implant_process_names"])
    c2 = set(spec["c2_ips_corroborating"])
    files = tuple(spec["implant_file_basenames"])

    sys.stderr.write("[evbase] pass 1/2: netflow table...\n"); sys.stderr.flush()
    netflow = c1.build_tables(inputs, max_records)   # uuid -> (remoteAddress, remotePort)

    sys.stderr.write("[evbase] pass 2/2: scoring every event...\n"); sys.stderr.flush()
    tp = fp = fn = tn = 0
    seen = events_tagged = events_ioc = 0
    for st, d in c1.insp_stream(inputs, max_records):
        if st != "Event":
            continue
        seen += 1
        et = insp._enum(d.get("type"))

        # detector: fire iff the event matches any ATT&CK rule (no correlation)
        alert = bool(c1.tag_event(et, d, netflow))

        # ground truth (independent of the detector): frozen event-level IOC rule
        ioc = False
        ts = d.get("timestampNanos")
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            ts = None
        if ts is not None and _inwin(ts, wins):
            ex = c1._props(d).get("exec")
            pobj = insp._uuid(d.get("predicateObject"))
            if ex in implant:
                ioc = True
            elif et in CONNECT:
                endp = netflow.get(pobj)
                if endp and endp[0] in c2:
                    ioc = True
            elif et in FILEOUT:
                bn = _basename(c1._str(d.get("predicateObjectPath")))
                if bn and bn.startswith(files):
                    ioc = True

        if alert:
            events_tagged += 1
        if ioc:
            events_ioc += 1
        if alert and ioc:
            tp += 1
        elif alert and not ioc:
            fp += 1
        elif (not alert) and ioc:
            fn += 1
        else:
            tn += 1

        if seen % 5_000_000 == 0:
            sys.stderr.write("[evbase]   %s events...\n" % f"{seen:,}"); sys.stderr.flush()

    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * prec * rec / (prec + rec)) if (prec == prec and rec == rec and (prec + rec)) else float("nan")

    summary = {
        "events_scanned": seen, "events_firing_alert": events_tagged,
        "events_ioc_ground_truth": events_ioc,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": round(prec, 6) if prec == prec else None,
        "recall": round(rec, 6) if rec == rec else None,
        "f1": round(f1, 6) if f1 == f1 else None,
        "note": "Binary event-level detector (fire iff any ATT&CK rule matches); "
                "no sequence/temporal/context correlation, no path aggregation.",
        "max_records": max_records,
    }
    out_dir = os.path.join(folder, out_name); os.makedirs(out_dir, exist_ok=True)
    json.dump(summary, open(os.path.join(out_dir, "baseline_eventlevel_summary.json"), "w"),
              indent=2, default=str)

    print("Frozen event-level ATT&CK baseline (no correlation, no paths)")
    print("=" * 64)
    print("events scanned        : %s" % f"{seen:,}")
    print("events firing an alert : %s" % f"{events_tagged:,}")
    print("events that are IOCs   : %s" % f"{events_ioc:,}")
    print("confusion  TP=%d  FP=%d  FN=%d  TN=%d" % (tp, fp, fn, tn))
    print("precision=%.6f  recall=%.6f  F1=%.6f" % (prec, rec, f1))
    print("\n[evbase] wrote %s/baseline_eventlevel_summary.json" % out_dir)
    return summary


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--folder", required=True)
    ap.add_argument("--max-records", type=int, default=0)
    a = ap.parse_args()
    run(a.folder, a.max_records)
