#!/usr/bin/env python3
"""
theia_analyze.py -- turn the THEIA stage-2 outputs into the paper's results
figure, tables, and a draft results paragraph. Run by Claude in the workspace on
the uploaded scores_all.csv / stage2_summary.json. No fabrication: every number
printed comes straight from those files.

USAGE
  python3 theia_analyze.py --scores scores_all.csv --summary stage2_summary.json --out .
"""
from __future__ import annotations
import argparse, csv, json, os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

NAVY="#0F274D"; STEEL="#5F7CA8"; INK="#1E293B"; BODY="#475569"; GRN="#1A8F55"; GREY="#94A3B8"
for fam in ("Poppins", "Liberation Sans", "DejaVu Sans"):
    try:
        plt.rcParams["font.family"] = fam; break
    except Exception:
        continue


def _f(x):
    try: return float(x)
    except (TypeError, ValueError): return None


def load(scores_path, summary_path):
    rows = []
    with open(scores_path, newline="") as f:
        for r in csv.DictReader(f):
            r["R"] = _f(r.get("R")); r["S_seq"] = _f(r.get("S_seq"))
            r["S_temp"] = _f(r.get("S_temp")); r["S_ctx"] = _f(r.get("S_ctx"))
            r["baseline_evidence"] = _f(r.get("baseline_evidence"))
            r["n_ioc"] = _f(r.get("n_ioc")); r["n_steps"] = _f(r.get("n_steps"))
            rows.append(r)
    summ = json.load(open(summary_path)) if summary_path and os.path.exists(summary_path) else {}
    return rows, summ


def shortlist_to_catch_all(rows):
    """Rank by R desc; smallest top-k that contains every attack path."""
    ordered = sorted([r for r in rows if r["R"] is not None], key=lambda r: r["R"], reverse=True)
    attacks = [i for i, r in enumerate(ordered) if r["label"] == "attack"]
    if not attacks:
        return None, 0, len(ordered)
    k = max(attacks) + 1
    return k, len(attacks), len(ordered)


def fig_results(rows, summ, out_png):
    fig, (axL, axR) = plt.subplots(1, 2, figsize=(12.0, 4.6))

    # ---- Left: ROC-AUC, method vs baseline vs ablation ----
    abl = summ.get("ablation", {})
    method_roc = (summ.get("method") or {}).get("ROC_AUC")
    base_roc = (summ.get("baseline_evidence_count") or {}).get("ROC_AUC")
    bars = []
    if abl.get("seq"): bars.append(("Sequence only", abl["seq"].get("ROC_AUC"), STEEL))
    if abl.get("seq+temp"): bars.append(("+ Timing", abl["seq+temp"].get("ROC_AUC"), STEEL))
    if abl.get("seq+temp+ctx"): bars.append(("+ Context (full)", abl["seq+temp+ctx"].get("ROC_AUC"), NAVY))
    if base_roc is not None: bars.append(("Baseline (count)", base_roc, GREY))
    bars = [(lab, v, c) for (lab, v, c) in bars if v is not None]
    if bars:
        labs = [b[0] for b in bars]; vals = [b[1] for b in bars]; cols = [b[2] for b in bars]
        y = range(len(bars))
        axL.barh(list(y), vals, color=cols, height=0.62, zorder=3)
        axL.set_yticks(list(y)); axL.set_yticklabels(labs, fontsize=11, color=INK)
        axL.invert_yaxis()
        axL.set_xlim(0, 1.0); axL.set_xlabel("ROC-AUC", fontsize=11, color=BODY)
        for i, v in enumerate(vals):
            axL.text(min(v + 0.02, 0.98), i, "%.3f" % v, va="center", fontsize=10.5, color=INK)
        axL.axvline(0.5, color=GREY, lw=1, ls=":", zorder=1)
        axL.set_title("Detection quality on THEIA", fontsize=12.5, color=NAVY, weight="bold")
        for s in ("top", "right"): axL.spines[s].set_visible(False)

    # ---- Right: R-score separation, attack vs benign ----
    atk = [r["R"] for r in rows if r["label"] == "attack" and r["R"] is not None]
    ben = [r["R"] for r in rows if r["label"] == "benign" and r["R"] is not None]
    if ben:
        axR.hist(ben, bins=30, color=STEEL, alpha=0.55, label="Benign (%d)" % len(ben), zorder=2)
    if atk:
        for i, v in enumerate(atk):
            axR.axvline(v, color=GRN, lw=2, zorder=4, label=("Attack (%d)" % len(atk)) if i == 0 else None)
    axR.set_xlabel("Risk score R(p)", fontsize=11, color=BODY)
    axR.set_ylabel("Benign paths", fontsize=11, color=BODY)
    axR.set_title("Attack vs benign separation", fontsize=12.5, color=NAVY, weight="bold")
    if atk or ben: axR.legend(fontsize=10, frameon=False)
    for s in ("top", "right"): axR.spines[s].set_visible(False)

    plt.tight_layout()
    fig.savefig(out_png, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def write_md(rows, summ, out_md):
    k, n_atk, n_tot = shortlist_to_catch_all(rows)
    pc = summ.get("path_counts", {})
    method = summ.get("method", {}); base = summ.get("baseline_evidence_count", {})
    abl = summ.get("ablation", {}); ws = summ.get("weight_sensitivity", {})
    comp = summ.get("attack_lineage_or_dataflow_components")

    L = []
    L.append("# THEIA results (draft, numbers computed from the real run)\n")
    L.append("Paths: %s\n" % pc)
    if comp is not None:
        L.append("Attack components (distinct causal clusters): %s\n" % comp)
    if k:
        L.append("Shortlist to surface all %d attack paths: top **%d** of %d ranked paths.\n"
                 % (n_atk, k, n_tot))
    L.append("")
    L.append("## Headline")
    if method.get("ROC_AUC") is not None:
        L.append("- Method (balanced 0.5/0.3/0.2): ROC-AUC **%s**, PR-AUC %s"
                 % (method.get("ROC_AUC"), method.get("PR_AUC")))
    if base.get("ROC_AUC") is not None:
        L.append("- Baseline (evidence count, no correlation): ROC-AUC **%s**, PR-AUC %s"
                 % (base.get("ROC_AUC"), base.get("PR_AUC")))
    if method.get("attack_R_min") is not None:
        L.append("- Attack R range %s..%s ; benign max %s (p99 %s)"
                 % (method.get("attack_R_min"), method.get("attack_R_max"),
                    method.get("benign_R_max"), method.get("benign_R_p99")))
    L.append("")
    L.append("## Ablation (does each signal add?)")
    L.append("| Signals | ROC-AUC | PR-AUC |")
    L.append("|---|---|---|")
    for key, lab in (("seq", "Sequence only"), ("seq+temp", "+ Timing"),
                     ("seq+temp+ctx", "+ Context (full)")):
        if abl.get(key):
            L.append("| %s | %s | %s |" % (lab, abl[key].get("ROC_AUC"), abl[key].get("PR_AUC")))
    L.append("")
    if ws:
        L.append("## Weight sensitivity")
        L.append("| Profile | ROC-AUC | PR-AUC |")
        L.append("|---|---|---|")
        for name, v in ws.items():
            L.append("| %s | %s | %s |" % (name, v.get("ROC_AUC"), v.get("PR_AUC")))
        L.append("")

    # ---- honest narrative scaffold (facts filled; interpretation left for review) ----
    L.append("## Draft paragraph")
    m = method.get("ROC_AUC"); b = base.get("ROC_AUC")
    seq = (abl.get("seq") or {}).get("ROC_AUC"); full = (abl.get("seq+temp+ctx") or {}).get("ROC_AUC")
    para = []
    para.append("We applied the frozen method, unchanged, to the DARPA Transparent Computing "
                "Engagement 3 THEIA host, adapting only the dataset-specific tagging and "
                "transcribing ground truth from the TA5.1 report.")
    if k and n_tot:
        para.append("Of %d behavioral paths constructed from the telemetry, surfacing all %d "
                     "documented attack paths required reviewing the top %d ranked paths."
                     % (n_tot, n_atk, k))
    if m is not None and b is not None:
        if abs(m - b) < 0.02:
            para.append("As on CADETS, the full correlation (ROC-AUC %s) and the simple "
                        "evidence-count baseline (ROC-AUC %s) performed comparably, indicating "
                        "the earlier finding is not specific to CADETS." % (m, b))
        elif m > b:
            para.append("Unlike CADETS, the full correlation (ROC-AUC %s) outperformed the "
                        "evidence-count baseline (ROC-AUC %s), indicating the richer THEIA "
                        "telemetry lets the correlation signals contribute measurable value."
                        % (m, b))
        else:
            para.append("On THEIA the evidence-count baseline (ROC-AUC %s) edged the full "
                        "correlation (ROC-AUC %s); we discuss why below." % (b, m))
    if seq is not None and full is not None:
        if abs(full - seq) < 0.02:
            para.append("The ablation shows timing and context added little beyond sequence "
                        "alignment alone (%s vs %s)." % (full, seq))
        else:
            para.append("The ablation shows the full signal set (%s) improved on sequence "
                        "alignment alone (%s)." % (full, seq))
    L.append(" ".join(para))
    L.append("")
    L.append("_[Interpretation sentences above are generated from the real numbers; review and "
             "adjust wording before use. No value here is invented.]_")

    open(out_md, "w").write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scores", required=True)
    ap.add_argument("--summary", default=None)
    ap.add_argument("--out", default=".")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rows, summ = load(a.scores, a.summary)
    fig_results(rows, summ, os.path.join(a.out, "fig_theia_results.png"))
    write_md(rows, summ, os.path.join(a.out, "results_theia.md"))
    k, n_atk, n_tot = shortlist_to_catch_all(rows)
    print("THEIA analyze: %d paths, %d attack; shortlist top-%s catches all."
          % (n_tot, n_atk, k))
    print("wrote fig_theia_results.png and results_theia.md to", a.out)


if __name__ == "__main__":
    main()
