#!/usr/bin/env python3
"""
scoring.py -- the frozen scoring core for
"Sequence-Aware Detection of APT Defense Evasion Using Behavioral Correlation."

This module implements ONLY the definitions frozen in the design specification. It
contains no data loading, no labels, no thresholds learned from data. The data
layer (Pass 2) will feed it observed paths; this file decides how a path scores.

Frozen pieces implemented here
------------------------------
1. R : the reference structure -- a directed, partially-ordered STAGE graph whose
   directed edges are ONLY the ones with external-transition evidence or logical
   precedence (see R_provenance.csv). Each stage admits a set of ATT&CK techniques.
2. P_max(R) : the maximal admissible stage-paths (the reference chains S_seq
   compares against).
3. S_seq  : reference-chain coverage, Dice-normalized LCS over P_max(R).
4. S_temp : order-respecting coherence within a fixed correlation horizon T.
5. S_ctx  : two-tier entity coupling (single-host adjusted: host tier dropped).
6. R(p)   : 0.5*S_seq + 0.3*S_temp + 0.2*S_ctx, with the prespecified sensitivity
            profiles and the seq -> seq+temp -> seq+temp+ctx ablation.

ONE MODELING CHOICE FLAGGED FOR REVIEW (see note at bottom): because the strict
edge rule keeps R's directed edges sparse, the maximal reference chains are
short. `reference_paths()` therefore also supports a documented "tactic-closure"
variant that composes justified edges through shared predecessors. The default
is the strict variant; nothing switches without your say-so.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from itertools import product
from typing import Dict, List, Sequence, Tuple, Optional


# --------------------------------------------------------------------------- #
# 1. Reference structure R (stages, admissible techniques, justified edges)
# --------------------------------------------------------------------------- #
# Stage -> admissible ATT&CK techniques (v19.2). Membership is from ATT&CK;
# the stage ORDERING below is from justified edges only.
STAGE_TECHNIQUES: Dict[str, set] = {
    "IA":    {"T1190"},
    "FOOT":  {"T1505.003", "T1620", "T1059"},
    "PE":    {"T1068", "T1548"},
    "C2":    {"T1071.001", "T1090", "T1572"},
    "DISC":  {"T1016", "T1046", "T1018", "T1135", "T1082",
              "T1087.001", "T1057", "T1033"},
    "INJ":   {"T1055"},
    "IR":    {"T1070", "T1070.004"},
    "EXFIL": {"T1041"},
    # Unordered admissible node: imposes no edge (see R_provenance.csv).
    "STG":   {"T1105"},
}

# Directed edges with their justification (kept in code so the graph is auditable).
#   ("A","B","external") or ("A","B","logical")
JUSTIFIED_EDGES: List[Tuple[str, str, str]] = [
    ("IA",   "FOOT", "external"),   # S3 both cases; S2
    ("FOOT", "PE",   "external"),   # S3 Case 2; S2
    ("FOOT", "C2",   "logical"),    # callback needs a running foothold
    ("FOOT", "DISC", "external"),   # S3 Case 1; S2
    ("PE",   "DISC", "external"),   # S2 escalate -> internal recon
    ("FOOT", "INJ",  "logical"),    # injection needs an execution context
    ("C2",   "IR",   "external"),   # trace removal after on-host activity (S3 C2)
    ("DISC", "IR",   "external"),
    ("INJ",  "IR",   "external"),
    ("C2",   "EXFIL", "external"),  # mission activity -> exfil (S3 Case 1; S2)
    ("DISC", "EXFIL", "external"),
    ("INJ",  "EXFIL", "external"),
    ("IR",   "EXFIL", "external"),
]

# STG participates in no JUSTIFIED_EDGES by design (unordered admissible node).


def _adjacency() -> Dict[str, List[str]]:
    adj: Dict[str, List[str]] = {s: [] for s in STAGE_TECHNIQUES}
    for a, b, _ in JUSTIFIED_EDGES:
        adj[a].append(b)
    return adj


def technique_to_stage(tech: str) -> Optional[str]:
    """Map an ATT&CK technique id to its R stage (None if not in R's vocabulary)."""
    for stage, techs in STAGE_TECHNIQUES.items():
        if tech in techs:
            return stage
    return None


def _all_simple_paths(adj, start, sinks) -> List[List[str]]:
    """All simple paths from `start` to any stage in `sinks`."""
    out: List[List[str]] = []

    def dfs(node, path):
        if node in sinks and len(path) > 1:
            out.append(list(path))
            # do not return: a sink may still have outgoing edges (e.g. IR->EXFIL)
        for nxt in adj[node]:
            if nxt not in path:
                path.append(nxt)
                dfs(nxt, path)
                path.pop()

    dfs(start, [start])
    return out


def _ordered_stage_graph():
    """R's stages that carry ordering (STG is unordered -> excluded), with succ/pred."""
    nodes = [s for s in STAGE_TECHNIQUES if s != "STG"]
    succ = {n: set() for n in nodes}
    pred = {n: set() for n in nodes}
    for a, b, _ in JUSTIFIED_EDGES:
        if a in succ and b in succ:
            succ[a].add(b)
            pred[b].add(a)
    return nodes, succ, pred


_MUST = None
def _must_precede_closure():
    nodes, succ, _ = _ordered_stage_graph()
    reach = {n: set() for n in nodes}

    def dfs(src, cur):
        for nxt in succ[cur]:
            if nxt not in reach[src]:
                reach[src].add(nxt)
                dfs(src, nxt)

    for n in nodes:
        dfs(n, n)
    return reach


def must_precede(a, b):
    """True iff stage a is REQUIRED (by justified edges, transitively) before b."""
    global _MUST
    if _MUST is None:
        _MUST = _must_precede_closure()
    return b in _MUST.get(a, set())


def _all_linear_extensions(cap=5000):
    """Every ordering of the ordered stages consistent with the justified partial order."""
    nodes, succ, pred = _ordered_stage_graph()
    results = []

    def rec(placed, order):
        if len(results) >= cap:
            return
        if len(order) == len(nodes):
            results.append(list(order))
            return
        for n in nodes:
            if n in placed:
                continue
            if all(p in placed for p in pred[n]):
                placed.add(n); order.append(n)
                rec(placed, order)
                order.pop(); placed.discard(n)

    rec(set(), [])
    return results


def reference_paths(variant: str = "partial") -> List[List[str]]:
    """
    P_max(R): the admissible reference stage-paths S_seq compares against.

    variant="partial" (DEFAULT, post-review): every linear extension of R's
        justified partial order -- so a path that covers the kill chain in ANY
        order consistent with the few hard constraints (IA first, PE before DISC,
        IR/EXFIL last) matches a reference fully. Rewards coverage, penalizes only
        true order violations. This is the faithful partial-order reading.
    variant="strict": paths following only the literal justified edges (sparse).
    variant="closure": mid-stages from FOOT composed into longer chains.
    """
    if variant == "partial":
        return _all_linear_extensions()

    adj = _adjacency()
    sinks = {"EXFIL", "IR"}
    paths = _all_simple_paths(adj, "IA", sinks)

    if variant == "strict":
        return _dedup_maximal(paths)

    if variant == "closure":
        # Compose: any subset of {PE,C2,DISC,INJ} reachable from FOOT may appear
        # together, ordered by the partial order (PE before DISC), between FOOT
        # and the terminal {IR?,EXFIL}. This yields richer reference chains while
        # still never ordering two stages against a justified edge.
        mids_order = ["PE", "C2", "DISC", "INJ"]   # PE<DISC is the only hard rule
        rich: List[List[str]] = []
        for k in range(1, len(mids_order) + 1):
            for combo in _ordered_subsets(mids_order, k):
                if "PE" in combo and "DISC" in combo and combo.index("PE") > combo.index("DISC"):
                    continue  # respect PE -> DISC
                for tail in (["IR", "EXFIL"], ["EXFIL"]):
                    rich.append(["IA", "FOOT"] + combo + tail)
        return _dedup_maximal(rich)

    raise ValueError("variant must be 'partial', 'strict', or 'closure'")


def _ordered_subsets(items, k):
    """Order-preserving subsets of length k."""
    from itertools import combinations
    return [list(c) for c in combinations(items, k)]


def _dedup_maximal(paths: List[List[str]]) -> List[List[str]]:
    """Drop any path that is a (contiguous-or-not) subsequence of a longer one."""
    uniq = [list(p) for p in {tuple(p) for p in paths}]
    uniq.sort(key=len, reverse=True)
    kept: List[List[str]] = []
    for p in uniq:
        if not any(_is_subsequence(p, q) for q in kept if q is not p and len(q) > len(p)):
            kept.append(p)
    return kept


def _is_subsequence(a: Sequence, b: Sequence) -> bool:
    """True if a is a subsequence of b."""
    it = iter(b)
    return all(x in it for x in a)


# --------------------------------------------------------------------------- #
# 2. Observed path representation
# --------------------------------------------------------------------------- #
@dataclass
class Step:
    """One matched step of an observed path."""
    technique: str                      # ATT&CK id
    t_nanos: int                        # event timestamp (ns since epoch, UTC)
    ctx_tier_to_next: float = 0.0       # entity-coupling tier to the NEXT step
                                        # (1.0 lineage, 0.6 socket/session, 0 none)

    @property
    def stage(self) -> Optional[str]:
        return technique_to_stage(self.technique)


@dataclass
class ObservedPath:
    steps: List[Step] = field(default_factory=list)

    @property
    def stages(self) -> List[str]:
        return [s.stage for s in self.steps if s.stage is not None]

    @property
    def matched_steps(self) -> List[Step]:
        return [s for s in self.steps if s.stage is not None]


# --------------------------------------------------------------------------- #
# 3. S_seq : Dice-normalized LCS coverage over P_max(R)
# --------------------------------------------------------------------------- #
def _lcs_len(a: Sequence[str], b: Sequence[str]) -> int:
    """Length of the longest common subsequence of two stage sequences."""
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0]
        for j, y in enumerate(b, 1):
            cur.append(prev[j] if x != y else prev[j - 1] + 1)
            if cur[j] < cur[j - 1]:
                cur[j] = cur[j - 1]
            if cur[j] < prev[j]:
                cur[j] = prev[j]
        prev = cur
    return prev[-1]


def s_seq(path: ObservedPath, variant: str = "partial") -> float:
    """
    S_seq(p) = max over r in P_max(R) of 2*|LCS(p_stages, r)| / (|p_stages| + |r|).

    Stage-level matching: an observed technique matches a reference position if it
    is in that stage's admissible set (already reduced to stages here). Dice
    normalization removes the short-reference degeneracy.
    """
    p_stages = path.stages
    if not p_stages:
        return 0.0
    best = 0.0
    for r in reference_paths(variant):
        lcs = _lcs_len(p_stages, r)
        denom = len(p_stages) + len(r)
        if denom:
            best = max(best, 2.0 * lcs / denom)
    return best


# --------------------------------------------------------------------------- #
# 4. S_temp : order-respecting coherence within a fixed horizon T
# --------------------------------------------------------------------------- #
def _reachable(adj, src, dst, _seen=None) -> bool:
    if src == dst:
        return True
    if _seen is None:
        _seen = set()
    _seen.add(src)
    return any(n not in _seen and _reachable(adj, n, dst, _seen) for n in adj.get(src, []))


def s_temp(path: ObservedPath, T_seconds: float = 3600.0) -> float:
    """
    S_temp(p) = (1/(m-1)) * sum_i 1[ stage_i precedes stage_{i+1} in R  AND
                                     0 < dt_i <= T ].
    No reward for speed; T is a fixed engineering horizon (default 3600 s = 60 min).
    Undefined for m <= 1 -> returns 0.0 (caller excludes the temporal term).
    """
    steps = path.matched_steps
    if len(steps) < 2:
        return 0.0
    adj = _adjacency()
    T_ns = T_seconds * 1e9
    good = 0
    for i in range(len(steps) - 1):
        si, sj = steps[i].stage, steps[i + 1].stage
        dt = steps[i + 1].t_nanos - steps[i].t_nanos
        # Partial-order faithful: a transition is fine UNLESS it reverses a
        # justified order (the later stage was required before the earlier one).
        order_ok = (si == sj) or (not must_precede(sj, si))
        if order_ok and 0 < dt <= T_ns:
            good += 1
    return good / (len(steps) - 1)


# --------------------------------------------------------------------------- #
# 5. S_ctx : two-tier entity coupling (single-host adjusted)
# --------------------------------------------------------------------------- #
def s_ctx(path: ObservedPath, tiers: Tuple[float, float] = (1.0, 0.6)) -> float:
    """
    S_ctx(p) = (1/(m-1)) * sum_i tau(step_i, step_{i+1}),
    where tau is the strongest shared relation already resolved by the data layer
    into step.ctx_tier_to_next (1.0 lineage, 0.6 socket/session, 0 none).
    `tiers` lets the sensitivity analysis remap the two non-zero levels, e.g.
    (1.0,0.5) or binary (1,1); values are matched by nearest of the default tiers.
    """
    steps = path.matched_steps
    if len(steps) < 2:
        return 0.0
    hi, lo = tiers
    total = 0.0
    for s in steps[:-1]:
        v = s.ctx_tier_to_next
        if v >= 0.8:
            total += hi
        elif v >= 0.3:
            total += lo
        else:
            total += 0.0
    return total / (len(steps) - 1)


# --------------------------------------------------------------------------- #
# 6. Aggregate R(p), sensitivity profiles, ablation
# --------------------------------------------------------------------------- #
WEIGHTS_DEFAULT = (0.5, 0.3, 0.2)
WEIGHT_PROFILES = {
    "balanced_0.5_0.3_0.2": (0.5, 0.3, 0.2),
    "alignment_only_1_0_0": (1.0, 0.0, 0.0),
    "uniform_0.33": (1 / 3, 1 / 3, 1 / 3),
    "temporal_0.3_0.5_0.2": (0.3, 0.5, 0.2),
}


def risk(path: ObservedPath, weights=WEIGHTS_DEFAULT, T_seconds=3600.0,
         ctx_tiers=(1.0, 0.6), variant="partial") -> float:
    w1, w2, w3 = weights
    return (w1 * s_seq(path, variant)
            + w2 * s_temp(path, T_seconds)
            + w3 * s_ctx(path, ctx_tiers))


def ablation(path: ObservedPath, T_seconds=3600.0, ctx_tiers=(1.0, 0.6),
             variant="partial") -> Dict[str, float]:
    """seq -> seq+temp -> seq+temp+ctx, each renormalized to its active weights."""
    ss, st, sc = s_seq(path, variant), s_temp(path, T_seconds), s_ctx(path, ctx_tiers)
    return {
        "seq": ss,
        "seq+temp": (0.5 * ss + 0.3 * st) / 0.8,
        "seq+temp+ctx": 0.5 * ss + 0.3 * st + 0.2 * sc,
        "components": {"S_seq": ss, "S_temp": st, "S_ctx": sc},
    }


# --------------------------------------------------------------------------- #
# NOTE FOR REVIEW -- the one open modeling choice
# --------------------------------------------------------------------------- #
# The strict edge rule (audit) keeps R's directed edges sparse, so the maximal
# reference chains in `reference_paths("strict")` are short (e.g. IA->FOOT->C2->
# EXFIL). A real campaign that also does discovery and injection cannot be fully
# covered by any single strict chain, so S_seq is bounded below 1 for rich paths.
# That is a faithful consequence of only asserting evidence-backed edges.
# `variant="closure"` is provided as a documented alternative that lets mid-stages
# sharing the FOOT predecessor appear in one chain (still never violating a
# justified order such as PE->DISC). We keep "strict" as the default and will
# decide the variant together, informed by the real matched-path lengths.
if __name__ == "__main__":
    print("strict reference chains P_max(R):")
    for r in reference_paths("strict"):
        print("  ", " -> ".join(r))
    print("\nclosure reference chains (count):", len(reference_paths("closure")))
