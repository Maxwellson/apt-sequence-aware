#!/usr/bin/env python3
"""
attack_link_probe.py -- how are the attack's processes causally connected?

The first scored run fragmented the campaign into many lineage components, so
paths built from parent-child lineage ALONE were tiny. The frozen plan specifies
causal paths over lineage AND file/socket dataflow. Before rebuilding the path
constructor we confirm, from the telemetry, which relation actually links the
attack steps: parent-child lineage, a shared dropped file, or a shared C2 socket.

It restricts to the attack windows in one archive (default official-2 = Apr 12 &
13, the richest episodes and the smallest file), finds the attack-relevant
processes from the frozen spec, and reports how many connected components they
form under three connectivity rules:
    (1) lineage only
    (2) lineage + shared-file dataflow
    (3) lineage + shared-file + shared-C2-socket
Fewer components = the campaign hangs together. Nothing is scored.

USAGE (Jupyter, FOLDER defined):
    import importlib, attack_link_probe as p; importlib.reload(p)
    p.probe(FOLDER)                       # default official-2, Apr12/13 windows
"""

from __future__ import annotations
import os, json, sys
from collections import defaultdict

import cadets_e3_inspect as insp
import connector_stage1 as c1

def _iso(s):
    from datetime import datetime, timezone
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp() * 1e9)


class UF:
    def __init__(self): self.p = {}
    def find(self, x):
        self.p.setdefault(x, x); r = x
        while self.p[r] != r: r = self.p[r]
        while self.p[x] != r: self.p[x], x = r, self.p[x]
        return r
    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb: self.p[ra] = rb
    def ncomp(self, nodes):
        return len({self.find(n) for n in nodes})


def probe(folder, archive="ta1-cadets-e3-official-2.json.tar.gz",
          windows_iso=(("2018-04-12T17:55:00Z", "2018-04-12T18:45:00Z"),
                       ("2018-04-13T13:00:00Z", "2018-04-13T13:25:00Z"))):
    path = os.path.join(folder, archive)
    if not os.path.exists(path):
        sys.exit("archive not found: %s" % path)
    spec = json.load(open(os.path.join(folder, "labeling_spec.json")))
    implant = set(spec["implant_process_names"])
    c2 = set(spec["c2_ips_corroborating"])
    files = tuple(spec["implant_file_basenames"])
    web = c1.WEB_SERVERS
    wins = [(_iso(a), _iso(b)) for a, b in windows_iso]
    def inwin(ts): return any(a <= ts <= b for a, b in wins)

    # pass 1: netflow + lineage
    sys.stderr.write("[linkprobe] pass 1/2 ...\n"); sys.stderr.flush()
    netflow = {}
    parent = {}
    for st, d in insp._iter_file(path, 0):
        if st == "NetFlowObject":
            netflow[d.get("uuid")] = d.get("remoteAddress")
        elif st == "Subject":
            u, par = d.get("uuid"), insp._uuid(d.get("parentSubject"))
            if u and par: parent[u] = par
        elif st == "Event" and insp._enum(d.get("type")) == "EVENT_FORK":
            s = insp._uuid(d.get("subject")); ch = insp._uuid(d.get("predicateObject"))
            if s and ch: parent.setdefault(ch, s)

    # pass 2: gather attack-relevant events in windows
    sys.stderr.write("[linkprobe] pass 2/2 ...\n"); sys.stderr.flush()
    attack_subj = {}                      # subj -> exec
    subj_files = defaultdict(set)         # subj -> set(file uuid)
    subj_sock = defaultdict(set)          # subj -> set(netflow uuid)
    subj_c2ip = defaultdict(set)          # subj -> set(c2 ip)
    file_writers = defaultdict(set)       # file uuid -> subjects that wrote/created
    file_users = defaultdict(set)         # file uuid -> subjects that read/exec/unlink
    for st, d in insp._iter_file(path, 0):
        if st != "Event": continue
        ts = d.get("timestampNanos")
        try: ts = int(ts)
        except (TypeError, ValueError): continue
        if not inwin(ts): continue
        et = insp._enum(d.get("type"))
        ex = c1._props(d).get("exec")
        subj = insp._uuid(d.get("subject"))
        if not subj: continue
        pobj = insp._uuid(d.get("predicateObject"))
        ppath = c1._str(d.get("predicateObjectPath"))
        bn = (ppath.rsplit("/", 1)[-1] if ppath else None)
        is_attack = False
        if ex in implant:
            is_attack = True
        if et in ("EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG"):
            ip = netflow.get(pobj)
            if ip in c2:
                is_attack = True; subj_c2ip[subj].add(ip)
            if ex in web and ip and not any(ip.startswith(x) for x in ("10.", "128.55.", "127.")):
                is_attack = True
            if pobj: subj_sock[subj].add(pobj)
        if bn and bn.startswith(files):
            is_attack = True
        if is_attack:
            attack_subj.setdefault(subj, ex)
        # record file touches for dataflow (regardless, to link attack subjects)
        if et in ("EVENT_WRITE", "EVENT_CREATE_OBJECT") and pobj:
            file_writers[pobj].add(subj); subj_files[subj].add(pobj)
        elif et in ("EVENT_READ", "EVENT_OPEN", "EVENT_EXECUTE", "EVENT_UNLINK") and pobj:
            file_users[pobj].add(subj); subj_files[subj].add(pobj)

    A = set(attack_subj)
    if not A:
        print("No attack-relevant processes found in the windows."); return

    # connectivity under the three rules
    uf_lin = UF(); uf_linfile = UF(); uf_all = UF()
    for u in (uf_lin, uf_linfile, uf_all):
        for s in A: u.find(s)
    # lineage edges among attack subjects (walk parent chain, union when both in A)
    for s in A:
        cur = s
        for _ in range(50):
            par = parent.get(cur)
            if not par: break
            if par in A:
                uf_lin.union(s, par); uf_linfile.union(s, par); uf_all.union(s, par)
            cur = par
    # file dataflow edges (writer -> user of same file), both attack subjects
    file_edges = 0
    for fobj, ws in file_writers.items():
        us = file_users.get(fobj, set())
        for a in (ws | us):
            for b in (ws | us):
                if a != b and a in A and b in A:
                    uf_linfile.union(a, b); uf_all.union(a, b); file_edges += 1
    # socket / C2 edges (same netflow uuid, or same C2 ip, across attack subjects)
    sock_edges = 0
    ip_to_subj = defaultdict(set)
    for s in A:
        for ip in subj_c2ip.get(s, ()): ip_to_subj[ip].add(s)
    for ip, subs in ip_to_subj.items():
        subs = list(subs)
        for i in range(len(subs)):
            for j in range(i + 1, len(subs)):
                uf_all.union(subs[i], subs[j]); sock_edges += 1

    print("Attack-link probe (no scoring)")
    print("=" * 50)
    print("archive:", archive)
    print("attack-relevant processes in windows: %d" % len(A))
    from collections import Counter
    print("  by program:", dict(Counter(attack_subj.values()).most_common()))
    print("\nConnected components among attack processes:")
    print("  (1) lineage only              : %d components" % uf_lin.ncomp(A))
    print("  (2) lineage + file dataflow   : %d components  (file edges: %d)"
          % (uf_linfile.ncomp(A), file_edges))
    print("  (3) lineage + file + C2 socket: %d components  (C2-socket edges: %d)"
          % (uf_all.ncomp(A), sock_edges))
    print("\nInterpretation: the rule that collapses these to ~1-2 components is the")
    print("connectivity the path constructor should use.")
    # show a few attack processes and how they attach
    print("\nSample attack processes (exec, parent-in-attack?, #files, #C2ips):")
    for s in list(A)[:20]:
        print("  %-14s parent_in_A=%s  files=%d  c2ips=%s"
              % (attack_subj[s], parent.get(s) in A, len(subj_files.get(s, ())),
                 sorted(subj_c2ip.get(s, ()))[:3]))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("--folder", required=True)
    a = ap.parse_args(); probe(a.folder)
