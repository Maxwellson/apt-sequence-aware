#!/usr/bin/env python3
"""
connector_stage1_theia.py -- the THEIA "tagger" (v2, probe-calibrated).

THEIA (DARPA TC E3) counterpart of the CADETS tagger. Produces the SAME kind of
output -- candidate ATT&CK-technique "steps" keyed on BEHAVIOR, label-independent
-- so the FROZEN scoring core (scoring.py) runs on THEIA unchanged.

CALIBRATED TO THE REAL THEIA TELEMETRY (from theia_e3_probe.py on 1r):
  * THEIA does NOT inline the acting process on events (properties.exec = 0).
    The acting process is resolved via a SUBJECT-NAME table (event.subject UUID
    -> Subject record -> properties.map.path / cmdLine). Probe: 4822/4822 named.
  * THEIA does NOT put file paths on events (predicateObjectPath = null). The path
    lives on the FileObject record, so Pass 1 builds a FILEOBJECT-PATH table and
    file rules resolve event.predicateObject UUID -> path.
  * EVENT_EXECUTE carries the command line at properties.map.cmdLine, so discovery
    tools and interpreters are detected from the cmdLine's first token.
  * remoteAddress is unwrapped (may be a {"string": ...} union) before the
    internal/external test.
  * Process creation is EVENT_CLONE on THEIA (handled in stage 2 for lineage).

The technique VOCABULARY is unchanged from CADETS and stays within R
(scoring.STAGE_TECHNIQUES): nothing THEIA-favorable is added to R.

USAGE
  python3 connector_stage1_theia.py --folder . --max-records 300000   # dry run
  python3 connector_stage1_theia.py --folder .                        # full
"""

from __future__ import annotations
import os, glob, json, sys
from collections import Counter, defaultdict

import cadets_e3_inspect as insp   # format-agnostic CDM reader (works for THEIA)

# ---- frozen technique vocabulary (MUST stay within scoring.STAGE_TECHNIQUES) ----
WEB_SERVERS = {"nginx", "httpd", "apache", "apache2", "lighttpd"}
INTERPRETERS = {"bash", "sh", "dash", "zsh", "csh", "tcsh", "ksh",
                "python", "python2", "python3", "perl", "ruby", "lua", "php"}
DISCOVERY_TOOLS = {
    "ps": "T1057", "lsof": "T1057", "pgrep": "T1057", "top": "T1057",
    "whoami": "T1033", "id": "T1033", "w": "T1033", "who": "T1033", "logname": "T1033",
    "netstat": "T1046", "ss": "T1046", "nmap": "T1046", "sockstat": "T1046",
    "ifconfig": "T1016", "ip": "T1016", "arp": "T1016", "route": "T1016",
    "hostname": "T1082", "uname": "T1082", "lsb_release": "T1082",
}
ACCOUNT_FILES = {"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
                 "/etc/master.passwd", "/etc/spwd.db"}
AUTH_READERS = {"sudo", "su", "login", "sshd", "getty", "passwd", "pam",
                "systemd", "systemd-logind", "dbus-daemon", "accounts-daemon"}
STAGE_EXCLUDE_PREFIX = ("/dev/", "/var/log/", "/proc/", "/sys/", "/run/")
INTERNAL_PREFIXES = ("10.", "128.55.", "127.", "169.254.", "192.168.", "::1", "fe80")
_SKIP_PATH_VALUES = {None, "", "<unknown>", "N/A", "NA"}


# ---- tolerant field helpers ----
def _str(v):
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return v.get("string") if "string" in v else (next(iter(v.values())) if len(v) == 1 else None)
    return None


def _props(rec):
    if not isinstance(rec, dict):
        return {}
    p = rec.get("properties")
    if isinstance(p, dict) and isinstance(p.get("map"), dict):
        return p["map"]
    if isinstance(p, dict):
        return p
    return {}


def _basename(path):
    return path.rsplit("/", 1)[-1] if path else None


def _first_token_basename(cmdline):
    if not cmdline or not isinstance(cmdline, str) or not cmdline.strip():
        return None
    return _basename(cmdline.strip().split()[0])


def _ipv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _ipv6(ip):
    return ip.count(":") >= 2 and all(c in "0123456789abcdefABCDEF:." for c in ip)


def _is_external(ip):
    """External C2 only counts a real routable IP. THEIA records NETLINK, LOCAL
    and unix-socket 'addresses' as NetFlowObjects too; those are NOT network C2
    and must be excluded or T1071.001 floods with benign sockets."""
    ip = _str(ip)
    if not ip or ip in _SKIP_PATH_VALUES:
        return False
    if not (_ipv4(ip) or _ipv6(ip)):
        return False
    return not any(ip.startswith(pre) for pre in INTERNAL_PREFIXES)


def _inputs(folder):
    pats = ["ta1-theia-e3-official*.json.tar.gz", "ta1-theia-e3-official*.json.gz",
            "ta1-theia-e3-official*.json", "ta1-theia-e3-official*.bin.gz",
            "ta1-theia-e3-official*.bin", "ta1-theia-e3-official*"]
    seen, out = set(), []
    for pat in pats:
        for p in sorted(glob.glob(os.path.join(folder, pat))):
            if p not in seen:
                seen.add(p); out.append(p)
    return out


def insp_stream(inputs, max_records):
    for path in inputs:
        for st, d in insp._iter_file(path, max_records):
            if st is not None:
                yield st, d


# ---- name/path resolvers (THEIA-specific) ----
def _subject_name(subj_rec):
    """Resolve a Subject record's process name. Probe-confirmed: THEIA carries it
    at properties.map.path (e.g. '/sbin/init') or in cmdLine."""
    pm = _props(subj_rec)
    for k in ("name", "path", "exec"):
        v = _str(pm.get(k))
        if v and v not in _SKIP_PATH_VALUES:
            return _basename(v)
    cmd = _str(subj_rec.get("cmdLine")) or _str(pm.get("cmdLine"))
    bn = _first_token_basename(cmd)
    if bn:
        return bn
    v = _str(subj_rec.get("exec"))
    return _basename(v) if v else None


def _fileobject_path(fo_rec):
    """Resolve a FileObject's path. THEIA puts it on the record or its baseObject
    properties map; try the known CDM locations tolerantly."""
    for container in (fo_rec, fo_rec.get("baseObject") if isinstance(fo_rec, dict) else None):
        pm = _props(container)
        for k in ("path", "filename", "file_path", "pathname", "name"):
            v = _str(pm.get(k))
            if v and v not in _SKIP_PATH_VALUES:
                return v
    for k in ("predicateObjectPath", "path", "name"):
        v = _str(fo_rec.get(k)) if isinstance(fo_rec, dict) else None
        if v and v not in _SKIP_PATH_VALUES:
            return v
    return None


# ---- Pass 1: lookup tables (netflow endpoints, Subject names, FileObject paths) ----
def build_tables(inputs, max_records=0):
    netflow = {}
    subject_name = {}
    fileobj_path = {}
    for st, d in insp_stream(inputs, max_records):
        if st == "NetFlowObject":
            netflow[insp._uuid(d.get("uuid"))] = (_str(d.get("remoteAddress")), d.get("remotePort"))
        elif st == "Subject":
            u = insp._uuid(d.get("uuid"))
            if u:
                nm = _subject_name(d)
                if nm:
                    subject_name[u] = nm
        elif st == "FileObject":
            u = insp._uuid(d.get("uuid"))
            if u:
                fp = _fileobject_path(d)
                if fp:
                    fileobj_path[u] = fp
    return netflow, subject_name, fileobj_path


def acting_name(ev, subject_name):
    inline = _str(_props(ev).get("exec"))
    if inline:
        return _basename(inline)
    return subject_name.get(insp._uuid(ev.get("subject")))


def _event_path(ev, fileobj_path):
    """The file path an event touches: inline predicateObjectPath (CADETS) or the
    FileObject-path table (THEIA)."""
    p = _str(ev.get("predicateObjectPath"))
    if p and p not in _SKIP_PATH_VALUES:
        return p
    return fileobj_path.get(insp._uuid(ev.get("predicateObject")))


# ---- rules (same technique vocabulary as CADETS; THEIA-appropriate resolution) ----
def tag_event(et, ev, netflow, subject_name, fileobj_path):
    acting = acting_name(ev, subject_name)
    tags = []

    if et in ("EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG"):
        endp = netflow.get(insp._uuid(ev.get("predicateObject")))
        if endp and _is_external(endp[0]):
            where = "%s:%s" % (_str(endp[0]), endp[1])
            if acting in WEB_SERVERS:
                tags.append(("T1190", "%s outbound->%s" % (acting, where)))
            tags.append(("T1071.001", "%s->%s" % (acting, where)))

    elif et == "EVENT_EXECUTE":
        newprog = _basename(_event_path(ev, fileobj_path))
        if newprog is None:
            newprog = _first_token_basename(_str(_props(ev).get("cmdLine"))) or \
                      _basename(_str(_props(ev).get("exec")))
        if newprog in DISCOVERY_TOOLS:
            tags.append((DISCOVERY_TOOLS[newprog], newprog))
        elif newprog in INTERPRETERS:
            tags.append(("T1059", "%s->%s" % (acting or "?", newprog)))

    elif et in ("EVENT_WRITE", "EVENT_CREATE_OBJECT"):
        path = _event_path(ev, fileobj_path)
        if path and path not in _SKIP_PATH_VALUES and not path.startswith(STAGE_EXCLUDE_PREFIX):
            tags.append(("T1105", path))

    elif et == "EVENT_CHANGE_PRINCIPAL":
        tags.append(("PRIVCHG", acting or ""))

    elif et in ("EVENT_READ", "EVENT_OPEN"):
        path = _event_path(ev, fileobj_path)
        if path in ACCOUNT_FILES and acting not in AUTH_READERS:
            tags.append(("T1087.001", "%s %s" % (acting, path)))

    elif et == "EVENT_UNLINK":
        path = _event_path(ev, fileobj_path)
        if path and path not in _SKIP_PATH_VALUES:
            tags.append(("T1070.004", path))

    return tags


# ---- run ----
def run(folder, max_records=0, out_name="connector_stage1_theia_out", examples_per=4):
    inputs = _inputs(folder)
    if not inputs:
        sys.exit("No THEIA archives found in %s (looked for ta1-theia-e3-official*)" % folder)
    out_dir = os.path.join(folder, out_name)
    os.makedirs(out_dir, exist_ok=True)

    sys.stderr.write("[theia tagger] pass 1/2: netflow + subject + fileobject tables...\n"); sys.stderr.flush()
    netflow, subject_name, fileobj_path = build_tables(inputs, max_records)
    sys.stderr.write("[theia tagger]   netflows=%d subjects_named=%d file_paths=%d\n"
                     % (len(netflow), len(subject_name), len(fileobj_path))); sys.stderr.flush()

    tag_counts = Counter(); examples = defaultdict(list)
    events_seen = 0; events_tagged = 0

    sys.stderr.write("[theia tagger] pass 2/2: tagging...\n"); sys.stderr.flush()
    for st, d in insp_stream(inputs, max_records):
        if st != "Event":
            continue
        events_seen += 1
        et = insp._enum(d.get("type"))
        tags = tag_event(et, d, netflow, subject_name, fileobj_path)
        if tags:
            events_tagged += 1
            for tech, detail in tags:
                tag_counts[tech] += 1
                if len(examples[tech]) < examples_per:
                    examples[tech].append({"event_type": et, "detail": detail,
                                           "acting": acting_name(d, subject_name),
                                           "ts": d.get("timestampNanos")})
        if events_seen % 5_000_000 == 0:
            sys.stderr.write("[theia tagger]   %s events...\n" % f"{events_seen:,}"); sys.stderr.flush()

    summary = {"dataset": "THEIA-E3", "events_seen": events_seen, "events_tagged": events_tagged,
               "tag_counts": dict(tag_counts.most_common()),
               "subjects_named": len(subject_name), "file_paths": len(fileobj_path),
               "examples": {k: examples[k] for k in tag_counts},
               "not_observable": ["T1620 in-memory execution", "T1055 process injection"],
               "max_records": max_records}
    with open(os.path.join(out_dir, "tagger_summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=str)

    print("Connector Stage 1 THEIA (tagger v2) -- frozen technique vocabulary, no scoring/labels")
    print("=" * 74)
    print("events scanned : %s" % f"{events_seen:,}")
    print("events tagged  : %s  (%.2f%%)" % (f"{events_tagged:,}", 100 * events_tagged / max(events_seen, 1)))
    print("subjects named : %s   file paths resolved : %s" % (f"{len(subject_name):,}", f"{len(fileobj_path):,}"))
    print("\nCandidate steps per technique:")
    for tech, c in tag_counts.most_common():
        print("  %-10s %s" % (tech, f"{c:,}"))
    print("\nExamples:")
    for tech in tag_counts:
        print("  == %s ==" % tech)
        for ex in examples[tech]:
            print("     %s  acting=%s  %s" % (ex["event_type"], ex["acting"], ex["detail"]))
    print("\nNOT observable (documented, not tagged): T1620, T1055")
    print("[theia tagger] wrote %s/tagger_summary.json" % out_dir)
    return summary


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--folder", required=True)
    ap.add_argument("--max-records", type=int, default=0)
    a = ap.parse_args()
    run(a.folder, a.max_records)
