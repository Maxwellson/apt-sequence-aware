#!/usr/bin/env python3
"""
CADETS E3 structural inspection (Pass 1) -- NO attack scoring.

Purpose
-------
This is the first local pass of the hybrid workflow for the paper
"Sequence-Aware Detection of APT Defense Evasion Using Behavioral Correlation."
It reads the DARPA TC Engagement 3 CADETS telemetry in a STREAMING fashion
(never loading a whole file into memory) and reports the structural facts the
frozen design specification says we must establish before finalizing candidate-path
construction and the mechanism-dependent ATT&CK mappings:

  * which CDM record (datum) types are present, and how many of each;
  * timestamp coverage and per-UTC-day event counts (stream/day boundaries);
  * per-input-file date coverage (which file carries which day);
  * Event.type histogram;
  * process (Subject) lineage: how many subjects carry a parentSubject, and
    how many of those parent references resolve to a seen Subject;
  * FileObject / NetFlowObject distributions (incl. presence of remote
    address/port on netflows);
  * Principal / user distribution;
  * a bounded referential-integrity estimate for Event subject/predicate refs.

It deliberately computes NOTHING about attack vs. benign labels, no scores, no
reference graph R. It only describes the telemetry so we can finalize the
remaining design specification open items.

Formats handled (auto-detected per file)
----------------------------------------
  * Avro object-container files (magic bytes 'Obj\\x01'), optionally .gz
  * newline-delimited JSON (one TCCDMDatum per line), optionally .gz
  * .tar.gz / .tgz archives containing either of the above
If a file is raw length-prefixed Avro (Kafka dump, no container header), the
script says so and asks for the container/JSON encoding instead -- that case
needs schema/TCCDMDatum.avsc and a different reader.

Requirements
------------
  python3 -m pip install fastavro            # only needed for Avro-container input
(JSON input needs no third-party packages.)

Usage
-----
  python3 cadets_e3_inspect.py \
      --inputs /path/to/cadets/ta1-cadets-e3-official* \
      --out    ./cadets_e3_inspection

  # quick dry run on the first N records per file (sanity check before the full run):
  python3 cadets_e3_inspect.py --inputs '/path/to/cadets/*' --out ./insp --max-records 200000

Outputs (written into --out)
----------------------------
  summary.txt                 human-readable overview (also printed to stdout)
  summary.json                machine-readable version of everything below
  datum_type_counts.csv       count per CDM datum type
  event_type_histogram.csv    count per Event.type
  per_day_event_counts.csv    UTC date -> event count
  per_file_coverage.csv       input file -> record count, min/max event date

Send the whole --out directory back for the next step. Nothing in it contains
scoring or labels; it is purely structural.
"""

import argparse
import csv
import glob
import gzip
import io
import json
import os
import sys
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

CDM_NS = "com.bbn.tc.schema.avro.cdm18."
AVRO_MAGIC = b"Obj\x01"


# --------------------------------------------------------------------------- #
# Record iteration: yield (short_type_name, datum_dict) for each TCCDMDatum.
# --------------------------------------------------------------------------- #
def _short(name):
    """Strip the CDM namespace from a union branch name."""
    if name is None:
        return None
    return name[len(CDM_NS):] if name.startswith(CDM_NS) else name


def _extract_datum(tccdm, from_avro):
    """
    Given one TCCDMDatum (as a dict), return (short_type, datum_dict).

    Avro (fastavro, return_record_name=True): tccdm['datum'] is a tuple
        (branch_name, value_dict).
    JSON: tccdm['datum'] is a dict with a single key = branch name.
    """
    datum = tccdm.get("datum")
    if datum is None:
        return None, None
    if from_avro:
        if isinstance(datum, tuple) and len(datum) == 2:
            return _short(datum[0]), datum[1]
        # Some fastavro versions nest unions as {'branch': value}
        if isinstance(datum, dict) and len(datum) == 1:
            k = next(iter(datum))
            return _short(k), datum[k]
        return "UNKNOWN", datum if isinstance(datum, dict) else {}
    else:
        if isinstance(datum, dict) and len(datum) == 1:
            k = next(iter(datum))
            return _short(k), datum[k]
        if isinstance(datum, dict):
            # Already a flat record with a 'type' or similar; cannot infer branch.
            return "UNKNOWN", datum
        return "UNKNOWN", {}


def _open_maybe_gz(path):
    """Return a binary file object, transparently decompressing .gz."""
    if path.endswith(".gz") or path.endswith(".tgz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def _iter_tccdm_from_stream(binstream, max_records):
    """
    Yield (short_type, datum) from a single binary stream, auto-detecting
    Avro-container vs newline-delimited JSON. `binstream` must be seekable
    for the magic-byte sniff; we buffer the first bytes if not.
    """
    head = binstream.read(4)
    rest = binstream
    # Rebuild a seekable-enough stream that includes the head we consumed,
    # buffered so TextIOWrapper / fastavro get a proper binary buffer.
    stream = io.BufferedReader(_Prepend(head, rest))

    if head[:4] == AVRO_MAGIC:
        try:
            import fastavro
        except ImportError:
            raise RuntimeError(
                "This file is Avro-container format but 'fastavro' is not "
                "installed. Run:  python3 -m pip install fastavro"
            )
        reader = fastavro.reader(stream, return_record_name=True)
        n = 0
        for rec in reader:
            yield _extract_datum(rec, from_avro=True)
            n += 1
            if max_records and n >= max_records:
                return
    elif head[:1] in (b"{", b"["):
        # newline-delimited JSON (most common) or a JSON array.
        text = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
        n = 0
        for line in text:
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield _extract_datum(rec, from_avro=False)
            n += 1
            if max_records and n >= max_records:
                return
    else:
        raise RuntimeError(
            "Unrecognized format (first bytes %r). If this is a raw, "
            "length-prefixed Avro/Kafka dump with no container header, it "
            "needs schema/TCCDMDatum.avsc and a different reader -- tell me "
            "and I will adjust the script. Otherwise re-download the "
            "Avro-container (.bin) or JSON encoding." % head
        )


class _Prepend(io.RawIOBase):
    """Wrap a stream so that `head` bytes already read are yielded first."""
    def __init__(self, head, rest):
        self._head = head
        self._rest = rest

    def readable(self):
        return True

    def readinto(self, b):
        if self._head:
            n = min(len(b), len(self._head))
            b[:n] = self._head[:n]
            self._head = self._head[n:]
            return n
        data = self._rest.read(len(b))
        if not data:
            return 0
        n = len(data)
        b[:n] = data
        return n


def _iter_file(path, max_records):
    """Yield (short_type, datum) from one input path (file or tar.gz)."""
    if path.endswith(".tar.gz") or (path.endswith(".tgz") and tarfile.is_tarfile(path)):
        with tarfile.open(path, "r:gz") as tf:
            for member in tf:
                if not member.isfile():
                    continue
                f = tf.extractfile(member)
                if f is None:
                    continue
                yield from _iter_tccdm_from_stream(f, max_records)
    else:
        with _open_maybe_gz(path) as f:
            yield from _iter_tccdm_from_stream(f, max_records)


# --------------------------------------------------------------------------- #
# Field helpers (tolerant to Avro-union vs JSON shapes).
# --------------------------------------------------------------------------- #
def _uuid(val):
    """CDM UUIDs appear as strings or {'com...UUID': 'xxxx'} unions; normalize."""
    if val is None:
        return None
    if isinstance(val, str):
        return val
    if isinstance(val, dict) and len(val) == 1:
        return next(iter(val.values()))
    if isinstance(val, tuple) and len(val) == 2:
        return val[1]
    return str(val)


def _enum(val):
    """Enum fields are plain strings in both encodings."""
    if isinstance(val, str):
        return val
    if isinstance(val, dict) and len(val) == 1:
        return next(iter(val.values()))
    return val


# --------------------------------------------------------------------------- #
# Main inspection pass.
# --------------------------------------------------------------------------- #
def inspect(inputs, out_dir, max_records, ref_cap):
    os.makedirs(out_dir, exist_ok=True)

    datum_counts = Counter()
    event_type_hist = Counter()
    per_day_events = Counter()                 # UTC date str -> count
    per_file = {}                              # path -> dict(records,min_ts,max_ts)

    subject_uuids = set()
    object_uuids = set()                       # files, netflows, pipes, etc.
    principal_uuids = set()

    subjects_with_parent = 0
    parent_refs = []                           # capped sample of parent UUIDs
    subject_type_hist = Counter()
    file_type_hist = Counter()
    netflow_with_remote = 0
    netflow_total = 0
    principal_users = Counter()

    # bounded referential-integrity sample for Event refs
    unresolved_sample = []                     # capped list of (field, uuid)
    event_ref_total = 0
    event_ref_resolved_inorder = 0

    ts_min = None
    ts_max = None

    def note_ts(path, ns):
        nonlocal ts_min, ts_max
        if ns is None:
            return
        try:
            ns = int(ns)
        except (TypeError, ValueError):
            return
        if ns <= 0:
            return
        if ts_min is None or ns < ts_min:
            ts_min = ns
        if ts_max is None or ns > ts_max:
            ts_max = ns
        day = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d")
        per_day_events[day] += 1
        pf = per_file[path]
        pf["records"] += 1
        if pf["min_ts"] is None or ns < pf["min_ts"]:
            pf["min_ts"] = ns
        if pf["max_ts"] is None or ns > pf["max_ts"]:
            pf["max_ts"] = ns

    all_object_uuids = object_uuids  # alias for clarity in ref check

    for path in inputs:
        per_file[path] = {"records": 0, "min_ts": None, "max_ts": None}
        sys.stderr.write("[inspect] reading %s\n" % path)
        sys.stderr.flush()
        count_here = 0
        for short_type, datum in _iter_file(path, max_records):
            if short_type is None:
                continue
            datum_counts[short_type] += 1
            count_here += 1

            if short_type == "Event":
                et = _enum(datum.get("type"))
                if et is not None:
                    event_type_hist[et] += 1
                note_ts(path, datum.get("timestampNanos"))
                # referential integrity (bounded)
                for field in ("subject", "predicateObject", "predicateObject2"):
                    ref = _uuid(datum.get(field))
                    if ref is None:
                        continue
                    event_ref_total += 1
                    if ref in subject_uuids or ref in object_uuids or ref in principal_uuids:
                        event_ref_resolved_inorder += 1
                    elif len(unresolved_sample) < ref_cap:
                        unresolved_sample.append((field, ref))

            elif short_type == "Subject":
                u = _uuid(datum.get("uuid"))
                if u:
                    subject_uuids.add(u)
                subject_type_hist[_enum(datum.get("type"))] += 1
                parent = _uuid(datum.get("parentSubject"))
                if parent:
                    subjects_with_parent += 1
                    if len(parent_refs) < ref_cap:
                        parent_refs.append(parent)

            elif short_type == "FileObject":
                u = _uuid(datum.get("uuid"))
                if u:
                    object_uuids.add(u)
                file_type_hist[_enum(datum.get("type"))] += 1

            elif short_type == "NetFlowObject":
                u = _uuid(datum.get("uuid"))
                if u:
                    object_uuids.add(u)
                netflow_total += 1
                ra = datum.get("remoteAddress")
                rp = datum.get("remotePort")
                if ra not in (None, "", -1) or rp not in (None, "", -1):
                    netflow_with_remote += 1

            elif short_type == "Principal":
                u = _uuid(datum.get("uuid"))
                if u:
                    principal_uuids.add(u)
                uid = datum.get("userId")
                principal_users[_enum(uid)] += 1

            else:
                # UnnamedPipeObject, SrcSinkObject, RegistryKeyObject, Host,
                # MemoryObject, etc. -- record their UUID as an object if present.
                u = _uuid(datum.get("uuid"))
                if u:
                    object_uuids.add(u)

        sys.stderr.write("[inspect]   %s records\n" % f"{count_here:,}")

    # final resolution of the capped unresolved sample against the complete sets
    unresolved_final = 0
    for field, ref in unresolved_sample:
        if not (ref in subject_uuids or ref in object_uuids or ref in principal_uuids):
            unresolved_final += 1
    parent_resolved = sum(1 for p in parent_refs if p in subject_uuids)

    # ------------------------------------------------------------------- #
    # Assemble + write reports.
    # ------------------------------------------------------------------- #
    def iso(ns):
        return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat() if ns else None

    summary = {
        "inputs": inputs,
        "max_records_per_file": max_records,
        "total_records": sum(datum_counts.values()),
        "datum_type_counts": dict(datum_counts.most_common()),
        "event_count": datum_counts.get("Event", 0),
        "timestamp_min_utc": iso(ts_min),
        "timestamp_max_utc": iso(ts_max),
        "per_day_event_counts": dict(sorted(per_day_events.items())),
        "subject_count": len(subject_uuids),
        "subject_type_hist": dict(subject_type_hist.most_common()),
        "subjects_with_parent": subjects_with_parent,
        "parent_ref_sample": len(parent_refs),
        "parent_ref_resolved_in_sample": parent_resolved,
        "fileobject_type_hist": dict(file_type_hist.most_common()),
        "netflow_total": netflow_total,
        "netflow_with_remote_endpoint": netflow_with_remote,
        "principal_count": len(principal_uuids),
        "principal_userid_hist": dict(principal_users.most_common(50)),
        "event_type_hist_top50": dict(event_type_hist.most_common(50)),
        "event_ref_total_checked": event_ref_total,
        "event_ref_resolved_inorder": event_ref_resolved_inorder,
        "event_ref_unresolved_sample_size": len(unresolved_sample),
        "event_ref_unresolved_after_full_sets": unresolved_final,
        "per_file_coverage": {
            p: {
                "records_with_ts": d["records"],
                "min_utc": iso(d["min_ts"]),
                "max_utc": iso(d["max_ts"]),
            } for p, d in per_file.items()
        },
    }

    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=str)

    def _csv(name, header, rows):
        with open(os.path.join(out_dir, name), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)

    _csv("datum_type_counts.csv", ["datum_type", "count"], datum_counts.most_common())
    _csv("event_type_histogram.csv", ["event_type", "count"], event_type_hist.most_common())
    _csv("per_day_event_counts.csv", ["utc_date", "event_count"], sorted(per_day_events.items()))
    _csv("per_file_coverage.csv",
         ["input_file", "records_with_ts", "min_utc", "max_utc"],
         [[p, d["records"], iso(d["min_ts"]), iso(d["max_ts"])] for p, d in per_file.items()])

    # human-readable
    lines = []
    lines.append("CADETS E3 structural inspection (Pass 1 -- no scoring, no labels)")
    lines.append("=" * 66)
    lines.append("Inputs: %d file(s)" % len(inputs))
    if max_records:
        lines.append("(DRY RUN: capped at %s records per file)" % f"{max_records:,}")
    lines.append("Total records: %s" % f"{summary['total_records']:,}")
    lines.append("")
    lines.append("Datum types:")
    for t, c in datum_counts.most_common():
        lines.append("  %-20s %s" % (t, f"{c:,}"))
    lines.append("")
    lines.append("Timestamp coverage (UTC): %s  ->  %s"
                 % (summary["timestamp_min_utc"], summary["timestamp_max_utc"]))
    lines.append("Per-day event counts:")
    for day, c in sorted(per_day_events.items()):
        lines.append("  %s  %s" % (day, f"{c:,}"))
    lines.append("")
    lines.append("Subjects: %s   with parentSubject: %s"
                 % (f"{len(subject_uuids):,}", f"{subjects_with_parent:,}"))
    lines.append("  parent refs resolved in sample: %d / %d"
                 % (parent_resolved, len(parent_refs)))
    lines.append("Subject types: " + ", ".join("%s=%s" % (k, v) for k, v in subject_type_hist.most_common()))
    lines.append("FileObjects by type: " + ", ".join("%s=%s" % (k, v) for k, v in file_type_hist.most_common()))
    lines.append("NetFlowObjects: %s  (with remote endpoint: %s)"
                 % (f"{netflow_total:,}", f"{netflow_with_remote:,}"))
    lines.append("Principals: %s" % f"{len(principal_uuids):,}")
    lines.append("")
    lines.append("Event referential integrity (bounded sample cap=%d):" % ref_cap)
    lines.append("  event->object refs checked: %s" % f"{event_ref_total:,}")
    lines.append("  resolved at time of event (in-order): %s" % f"{event_ref_resolved_inorder:,}")
    lines.append("  unresolved sample re-checked against full sets: %d still unresolved"
                 % unresolved_final)
    lines.append("")
    lines.append("Per-file coverage:")
    for p, d in per_file.items():
        lines.append("  %s" % os.path.basename(p))
        lines.append("      records w/ ts: %s   %s -> %s"
                     % (f"{d['records']:,}", iso(d["min_ts"]), iso(d["max_ts"])))
    text = "\n".join(lines)
    with open(os.path.join(out_dir, "summary.txt"), "w") as f:
        f.write(text + "\n")
    print(text)
    print("\n[inspect] wrote reports to %s/" % out_dir)


def main():
    ap = argparse.ArgumentParser(description="CADETS E3 structural inspection (no scoring).")
    ap.add_argument("--inputs", nargs="+", required=True,
                    help="file paths or globs (e.g. '/data/cadets/ta1-cadets-e3-official*')")
    ap.add_argument("--out", default="cadets_e3_inspection", help="output directory")
    ap.add_argument("--max-records", type=int, default=0,
                    help="cap records read PER FILE (0 = no cap; use for a dry run)")
    ap.add_argument("--ref-cap", type=int, default=200000,
                    help="cap for the referential-integrity sample (memory bound)")
    args = ap.parse_args()

    paths = []
    for pat in args.inputs:
        expanded = sorted(glob.glob(pat))
        if expanded:
            paths.extend(expanded)
        elif os.path.exists(pat):
            paths.append(pat)
    if not paths:
        sys.exit("No input files matched: %s" % args.inputs)

    inspect(paths, args.out, args.max_records or 0, args.ref_cap)


if __name__ == "__main__":
    main()
