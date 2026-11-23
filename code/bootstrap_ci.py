#!/usr/bin/env python3
"""
bootstrap_ci.py -- stratified path-level bootstrap 95% CIs for the CADETS
ROC-AUC values reported in the paper. Reads scores_all.csv (the real per-path
score file) and resamples the positive and negative path populations
independently, which is the appropriate interval for a tiny positive class.

Reproduces the confidence intervals quoted in Section IV: sequence alignment
0.985 [0.97, 1.00], S_seq+S_temp 0.984 [0.97, 1.00], full R 0.943 [0.84, 1.00],
path-length separating robustly.

No fabrication: every number comes straight from scores_all.csv.

USAGE
  python3 bootstrap_ci.py scores_all.csv            # default 5000 resamples
  python3 bootstrap_ci.py scores_all.csv 10000 7    # resamples, seed
"""
import sys, csv
import numpy as np
from scipy.stats import rankdata


def auc(scores, y):
    r = rankdata(scores)
    n1 = y.sum()
    n0 = len(y) - n1
    if n1 == 0 or n0 == 0:
        return np.nan
    return (r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "scores_all.csv"
    B = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 42

    rows = list(csv.DictReader(open(path)))
    y = np.array([1 if r["label"] == "attack" else 0 for r in rows])
    nstep = np.array([float(r["n_steps"]) for r in rows])
    sseq = np.array([float(r["S_seq"]) for r in rows])
    stemp = np.array([float(r["S_temp"]) for r in rows])
    R = np.array([float(r["R"]) for r in rows])

    scorers = {
        "path-length": nstep,
        "S_seq": sseq,
        "S_seq+S_temp": 0.5 * sseq + 0.3 * stemp,
        "Full R": R,
    }

    pos = np.where(y == 1)[0]
    neg = np.where(y == 0)[0]
    rng = np.random.default_rng(seed)
    print(f"n paths {len(y)}  positives {int(y.sum())}  resamples {B}  seed {seed}\n")
    for name, s in scorers.items():
        pt = auc(s, y)
        boot = np.empty(B)
        for b in range(B):
            idx = np.concatenate([
                rng.choice(pos, size=len(pos), replace=True),
                rng.choice(neg, size=len(neg), replace=True),
            ])
            boot[b] = auc(s[idx], y[idx])
        lo, hi = np.nanpercentile(boot, [2.5, 97.5])
        print(f"{name:14s} AUC={pt:.4f}  95% CI [{lo:.3f}, {hi:.3f}]")


if __name__ == "__main__":
    main()
