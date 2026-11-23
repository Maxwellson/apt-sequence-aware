#!/usr/bin/env python3
"""
connector_stage2_theia.py -- THEIA counterpart of connector_stage2.py.

IDENTICAL logic to the CADETS stage-2 connector (causal paths over lineage +
file/socket dataflow, path segmentation by horizon T, frozen scoring, baseline,
ablation, weight sensitivity). The ONLY differences are:

  * it imports connector_stage1_theia (the THEIA tagger) instead of the CADETS one;
  * it loads labeling_spec_theia.json (THEIA ground truth) instead of the CADETS spec;
  * it resolves the acting process via the THEIA Subject-name table (built in pass 1)
    rather than the inlined CADETS exec field;
  * input glob and messages say THEIA.

scoring.py is imported and used UNCHANGED (frozen). R, S_seq/S_temp/S_ctx, the
0.5/0.3/0.2 weights, the horizon T, the ablation and the sensitivity profiles are
all exactly as in the CADETS run. This is the same method applied to a second
dataset -- nothing is re-tuned.

USAGE
-----
  python3 connector_stage2_theia.py --folder /path/to/theia --T-seconds 3600
"""

from __future__ import annotations
import os, json, sys, csv
from collections import defaultdict, Counter
from datetime import datetime, timezone

import cadets_e3_inspect as insp
import connector_stage1_theia as c1
import scoring as S

TAG_TO_TECHNIQUE = {"PRIVCHG": "T1068"}
MAX_WRITERS = 3
MAX_USERS = 10
MAX_SOCK_SUBJ = 5


def _iso_to_ns(s):
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp() * 1e9)


def _episode_label(iso_start):
    s = iso_start.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return "%s %d" % (dt.strftime("%b"), dt.day)


def _load_spec(folder):
    spec = json.load(open(os.path.join(folder, "labeling_spec_theia.json")))
    if not spec.get("attack_windows_utc"):
        sys.exit("labeling_spec_theia.json has no attack_windows_utc -- fill it from the "
                 "THEIA section of tc_ground_truth_report_e3_update.pdf before the scored run.")
    spec["_win"] = [(_iso_to_ns(a), _iso_to_ns(b)) for a, b in spec["attack_windows_utc"]]
    spec["_episodes"] = [_episode_label(a) for a, b in spec["attack_windows_utc"]]
    spec["_implant"] = set(spec.get("implant_process_names", []))
    spec["_c2"] = set(spec.get("c2_ips_corroborating", []))
    spec["_files"] = tuple(spec.get("implant_file_basenames", []))
    return spec


def _inwin(ts, wins):
    return any(a <= ts <= b for a, b in wins)


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


def _basename(p):
    return p.rsplit("/", 1)[-1] if p else None


def _auc_pair(pos, neg):
    """ROC-AUC (Mann-Whitney) and PR-AUC (average precision)."""
    if not pos or not neg:
        return float("nan"), float("nan")
    allv = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    ranks = [0.0] * len(allv); j = 0
    while j < len(allv):
        k = j
        while k + 1 < len(allv) and allv[k + 1][0] == allv[j][0]:
            k += 1
        avg = (j + k) / 2.0 + 1
        for m in range(j, k + 1): ranks[m] = avg
        j = k + 1
    rsum = sum(ranks[m] for m in range(len(allv)) if allv[m][1] == 1)
    n1, n0 = len(pos), len(neg)
    roc = (rsum - n1 * (n1 + 1) / 2.0) / (n1 * n0)
    thr = sorted(set(pos + neg), reverse=True); ap = 0.0; prev = 0.0
    for t in thr:
        tp = sum(1 for v in pos if v >= t); fp = sum(1 for v in neg if v >= t)
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / len(pos)
        ap += (rec - prev) * prec; prev = rec
    return roc, ap


def run(folder, T_seconds=3600, out_name="stage2_theia_out", weight_profile="balanced_0.5_0.3_0.2"):
    inputs = c1._inputs(folder)
    if not inputs:
        sys.exit("No THEIA archives found in %s (looked for ta1-theia-e3-official*)" % folder)
    spec = _load_spec(folder)
    out_dir = os.path.join(folder, out_name); os.makedirs(out_dir, exist_ok=True)
    T_ns = T_seconds * 1e9

    # ---- Pass 1: lineage, netflow, SUBJECT NAMES, file writers, socket subjects ----
    sys.stderr.write("[s2 theia] pass 1/2: lineage + subject names + writers + sockets...\n"); sys.stderr.flush()
    parent = {}; netflow = {}; subject_name = {}; fileobj_path = {}
    file_writers = defaultdict(set); sock_subj = defaultdict(set)
    for st, d in c1.insp_stream(inputs, 0):
        if st == "Subject":
            u = insp._uuid(d.get("uuid")); par = insp._uuid(d.get("parentSubject"))
            if u and par: parent[u] = par
            if u:
                nm = c1._subject_name(d)
                if nm: subject_name[u] = nm
        elif st == "NetFlowObject":
            netflow[insp._uuid(d.get("uuid"))] = (c1._str(d.get("remoteAddress")), d.get("remotePort"))
        elif st == "FileObject":
            u = insp._uuid(d.get("uuid"))
            if u:
                fp = c1._fileobject_path(d)
                if fp: fileobj_path[u] = fp
        elif st == "Event":
            et = insp._enum(d.get("type")); subj = insp._uuid(d.get("subject"))
            if not subj: continue
            if et in ("EVENT_FORK", "EVENT_CLONE"):
                ch = insp._uuid(d.get("predicateObject"))
                if ch: parent.setdefault(ch, subj)
            elif et in ("EVENT_WRITE", "EVENT_CREATE_OBJECT"):
                f = insp._uuid(d.get("predicateObject"))
                if f and len(file_writers[f]) <= MAX_WRITERS: file_writers[f].add(subj)
            elif et in ("EVENT_CONNECT", "EVENT_SENDTO", "EVENT_ACCEPT"):
                nf = insp._uuid(d.get("predicateObject"))
                if nf and len(sock_subj[nf]) <= MAX_SOCK_SUBJ: sock_subj[nf].add(subj)
    sys.stderr.write("[s2 theia]   subjects_named=%d file_paths=%d written files=%d sockets=%d\n"
                     % (len(subject_name), len(fileobj_path), len(file_writers), len(sock_subj))); sys.stderr.flush()

    # ---- Pass 2: tagged steps + file users (for written files) ----
    sys.stderr.write("[s2 theia] pass 2/2: tagging + file users...\n"); sys.stderr.flush()
    subj_steps = defaultdict(list)
    file_users = defaultdict(set)
    seen = 0
    for st, d in c1.insp_stream(inputs, 0):
        if st != "Event": continue
        seen += 1
        et = insp._enum(d.get("type")); subj = insp._uuid(d.get("subject"))
        if subj and et in ("EVENT_READ", "EVENT_OPEN", "EVENT_EXECUTE", "EVENT_UNLINK"):
            f = insp._uuid(d.get("predicateObject"))
            if f in file_writers and len(file_users[f]) <= MAX_USERS:
                file_users[f].add(subj)
        tags = c1.tag_event(et, d, netflow, subject_name, fileobj_path)
        if not tags:
            if seen % 5_000_000 == 0:
                sys.stderr.write("[s2 theia]   %s events...\n" % f"{seen:,}"); sys.stderr.flush()
            continue
        ts = d.get("timestampNanos")
        try: ts = int(ts)
        except (TypeError, ValueError): continue
        subj = subj or "UNKNOWN"
        ex = c1.acting_name(d, subject_name)
        ioc = False
        if _inwin(ts, spec["_win"]):
            if ex in spec["_implant"]:
                ioc = True
            else:
                for tech, detail in tags:
                    if tech in ("T1190", "T1071.001"):
                        ip = detail.split("->")[-1].split(":")[0]
                        if ip in spec["_c2"]: ioc = True
                    if tech in ("T1105", "T1070.004"):
                        bn = _basename(detail)
                        if bn and spec["_files"] and bn.startswith(spec["_files"]): ioc = True
        for tech, detail in tags:
            subj_steps[subj].append((ts, TAG_TO_TECHNIQUE.get(tech, tech), ioc))
        if seen % 5_000_000 == 0:
            sys.stderr.write("[s2 theia]   %s events...\n" % f"{seen:,}"); sys.stderr.flush()

    # ---- connectivity over subjects that have tagged steps ----
    sys.stderr.write("[s2 theia] building components...\n"); sys.stderr.flush()
    tagged = set(subj_steps)
    uf = UF()
    for s in tagged: uf.find(s)
    for ch, par in parent.items():
        if ch in tagged and par in tagged: uf.union(ch, par)
    for f, ws in file_writers.items():
        us = file_users.get(f, set())
        members = [m for m in (ws | us) if m in tagged]
        for i in range(1, len(members)):
            uf.union(members[0], members[i])
    for nf, subs in sock_subj.items():
        members = [m for m in subs if m in tagged]
        for i in range(1, len(members)):
            uf.union(members[0], members[i])

    # ---- component -> time-ordered events -> paths (segment by T) ----
    comp = defaultdict(list)
    for subj, steps in subj_steps.items():
        root = uf.find(subj)
        for (ts, tech, ioc) in steps:
            comp[root].append((ts, tech, ioc, subj))
    paths = []
    for root, steps in comp.items():
        steps.sort(key=lambda x: x[0])
        seg = [steps[0]]
        for cur in steps[1:]:
            if cur[0] - seg[-1][0] <= T_ns: seg.append(cur)
            else: paths.append(seg); seg = [cur]
        paths.append(seg)

    # ---- label + score (method) + baseline ----
    w1b, w2b, w3b = S.WEIGHT_PROFILES[weight_profile]

    def to_sp(seg):
        collapsed = []
        seen_st = set()
        for (ts, tech, ioc, subj) in seg:
            stg = S.technique_to_stage(tech) or tech
            if stg not in seen_st:
                seen_st.add(stg)
                collapsed.append((ts, tech, subj))
        steps = []
        for i, (ts, tech, subj) in enumerate(collapsed):
            tier = 0.0
            if i + 1 < len(collapsed):
                s2 = collapsed[i + 1][2]
                tier = 1.0 if (subj == s2 or parent.get(s2) == subj or parent.get(subj) == s2) else 0.6
            steps.append(S.Step(technique=tech, t_nanos=ts, ctx_tier_to_next=tier))
        return S.ObservedPath(steps)

    rows = []; A = []; B = []
    attack_components = set()
    for seg in paths:
        n_ioc = sum(1 for s in seg if s[2])
        lab = "attack" if n_ioc >= 2 else ("benign" if n_ioc == 0 else "excluded")
        ioc_ts = [s[0] for s in seg if s[2]]
        episode = ""
        if ioc_ts:
            t0 = min(ioc_ts)
            for wi, (wa, wb) in enumerate(spec["_win"]):
                if wa <= t0 <= wb:
                    episode = spec["_episodes"][wi]; break
        sp = to_sp(seg)
        ss = S.s_seq(sp); st = S.s_temp(sp, T_seconds); sc = S.s_ctx(sp)
        R = w1b * ss + w2b * st + w3b * sc
        base = len(set(t for _, t, _, _ in seg))
        rows.append({"label": lab, "episode": episode, "n_steps": len(seg), "n_ioc": n_ioc,
                     "R": round(R, 4), "S_seq": round(ss, 3), "S_temp": round(st, 3),
                     "S_ctx": round(sc, 3), "baseline_evidence": base,
                     "stages": "-".join(t for _, t, _, _ in seg)[:140]})
        rec = {"ss": ss, "st": st, "sc": sc, "base": float(base)}
        if lab == "attack":
            A.append(rec); attack_components.add(uf.find(seg[0][3]))
        elif lab == "benign":
            B.append(rec)

    def auc_combo(fn):
        return _auc_pair([fn(a) for a in A], [fn(b) for b in B])

    m_roc, m_pr = auc_combo(lambda d: w1b * d["ss"] + w2b * d["st"] + w3b * d["sc"])
    b_roc, b_pr = auc_combo(lambda d: d["base"])
    weight_sens = {}
    for name, (x1, x2, x3) in S.WEIGHT_PROFILES.items():
        r, p = auc_combo(lambda d, x1=x1, x2=x2, x3=x3: x1 * d["ss"] + x2 * d["st"] + x3 * d["sc"])
        weight_sens[name] = {"ROC_AUC": round(r, 4) if r == r else None,
                             "PR_AUC": round(p, 4) if p == p else None}
    abl = {}
    for k, fn in (("seq", lambda d: d["ss"]),
                  ("seq+temp", lambda d: (0.5 * d["ss"] + 0.3 * d["st"]) / 0.8),
                  ("seq+temp+ctx", lambda d: 0.5 * d["ss"] + 0.3 * d["st"] + 0.2 * d["sc"])):
        r, p = auc_combo(fn)
        abl[k] = {"ROC_AUC": round(r, 4) if r == r else None,
                  "PR_AUC": round(p, 4) if p == p else None}

    m_neg = [w1b * b["ss"] + w2b * b["st"] + w3b * b["sc"] for b in B]
    m_pos = [w1b * a["ss"] + w2b * a["st"] + w3b * a["sc"] for a in A]
    counts = Counter(r["label"] for r in rows)

    summary = {
        "dataset": "THEIA-E3",
        "T_seconds": T_seconds, "weight_profile": weight_profile,
        "path_counts": dict(counts), "attack_paths": len(A), "benign_paths": len(B),
        "attack_lineage_or_dataflow_components": len(attack_components),
        "method": {"ROC_AUC": round(m_roc, 4) if m_roc == m_roc else None,
                   "PR_AUC": round(m_pr, 4) if m_pr == m_pr else None,
                   "attack_R_min": round(min(m_pos), 4) if m_pos else None,
                   "attack_R_max": round(max(m_pos), 4) if m_pos else None,
                   "benign_R_p99": round(sorted(m_neg)[int(0.99 * len(m_neg))], 4) if m_neg else None,
                   "benign_R_max": round(max(m_neg), 4) if m_neg else None},
        "baseline_evidence_count": {"ROC_AUC": round(b_roc, 4) if b_roc == b_roc else None,
                                    "PR_AUC": round(b_pr, 4) if b_pr == b_pr else None},
        "ablation": abl,
        "weight_sensitivity": weight_sens,
    }
    json.dump(summary, open(os.path.join(out_dir, "stage2_summary.json"), "w"), indent=2, default=str)
    rows.sort(key=lambda r: r["R"], reverse=True)
    cols = ["label", "episode", "n_steps", "n_ioc", "R", "S_seq", "S_temp", "S_ctx", "baseline_evidence", "stages"]
    with open(os.path.join(out_dir, "paths_top200.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for r in rows[:200]: w.writerow(r)
    with open(os.path.join(out_dir, "attack_paths.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for r in rows:
            if r["label"] == "attack": w.writerow(r)
    with open(os.path.join(out_dir, "scores_all.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for r in rows: w.writerow(r)

    print("Connector Stage 2 THEIA -- causal paths (lineage + file/socket), scored (frozen core)")
    print("=" * 74)
    print("T=%ds  default weights=%s" % (T_seconds, (w1b, w2b, w3b)))
    print("paths:", dict(counts), " attack=%d benign=%d" % (len(A), len(B)))
    print("attack components (expect ~one per documented THEIA episode): %d" % len(attack_components))
    if m_pos:
        print("METHOD  R(p): attack %.3f..%.3f   benign max %.3f  p99 %.3f"
              % (min(m_pos), max(m_pos), max(m_neg) if m_neg else 0, sorted(m_neg)[int(0.99*len(m_neg))] if m_neg else 0))
    print("METHOD   (balanced) ROC-AUC=%s  PR-AUC=%s" % (summary["method"]["ROC_AUC"], summary["method"]["PR_AUC"]))
    print("BASELINE (count)    ROC-AUC=%s  PR-AUC=%s" % (summary["baseline_evidence_count"]["ROC_AUC"], summary["baseline_evidence_count"]["PR_AUC"]))
    print("\nABLATION (does each term add?):")
    for k in ("seq", "seq+temp", "seq+temp+ctx"):
        print("   %-14s ROC-AUC=%s  PR-AUC=%s" % (k, abl[k]["ROC_AUC"], abl[k]["PR_AUC"]))
    print("\nWEIGHT SENSITIVITY:")
    for name, v in weight_sens.items():
        print("   %-24s ROC-AUC=%s  PR-AUC=%s" % (name, v["ROC_AUC"], v["PR_AUC"]))
    print("\n[s2 theia] wrote %s/ (stage2_summary.json, paths_top200.csv, attack_paths.csv, scores_all.csv)" % out_dir)
    return summary


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("--folder", required=True)
    ap.add_argument("--T-seconds", type=int, default=3600)
    a = ap.parse_args(); run(a.folder, a.T_seconds)
