# Frozen Design Specification

**Paper:** Sequence-Aware Detection of APT Defense Evasion Using Behavioral Correlation
**Authors:** Felix Olowononi, Joshua Enoch Maxwellson (Marymount University)

This document records the full detection design as it was fixed prior to scoring any attack-labelled data on the DARPA Transparent Computing CADETS and THEIA collections. No parameter below was tuned to the evaluation data. It is the "companion design specification" referenced in the paper.

---

## 1. Objective and hypothesis

Model a host intrusion as a temporal path through an externally grounded, MITRE ATT&CK–aligned precedence graph, and test whether a decomposed path score (sequence alignment + temporal consistency + contextual coupling) separates documented attack paths from benign candidate paths on real host-provenance telemetry. Each score term is measured separately so its individual contribution can be ablated.

The design is confirmatory for the method and exploratory for the datasets: the reference graph is built from external cyber threat intelligence, independently of the evaluation campaigns.

## 2. Reference precedence graph R (fixed)

Directed acyclic precedence graph over attack stages; an edge u ≺ v means stage u must precede stage v (other stages may occur between them). Admissible orderings P(R) are the linear extensions of the graph. Techniques are projected onto stages.

| Precedence edge | Admissible techniques | Source |
|---|---|---|
| IA ≺ Foothold | T1190 → T1505.003 / T1620 / T1059 | external |
| Foothold ≺ Priv. Esc. | T1068, T1548 | external |
| Foothold ≺ C2 | T1071.001, T1090, T1572 | logical |
| Foothold/PE ≺ Discovery | T1087.001, T1057, T1033, T1016, T1046, T1082 | external |
| Foothold ≺ Injection | T1055 | logical |
| {C2, Disc, Inj} ≺ Indicator Removal | T1070, T1070.004 | logical |
| {C2, Disc, Inj, IR} ≺ Exfiltration | T1041 | external |
| Staging (unordered) | T1105 | node only |

Sources: Mandiant Targeted Attack Lifecycle; CISA/joint advisory AA24-190A (APT40); MITRE ATT&CK v19.2 for technique/tactic definitions. "logical" = precedence inferred by the authors from stage semantics; "external" = supported by a cited source; "node only" = stage present with no ordering constraint.

## 3. Score definitions (fixed)

For a path p with m matched steps and stage sequence σ(p):

- **Sequence alignment** — Dice-normalized longest-common-subsequence coverage of σ(p) against the admissible orderings:
  S_seq(p) = max over r ∈ P(R) of 2·|LCS(σ(p), r)| / (|σ(p)| + |r|)

- **Temporal consistency** — fraction of consecutive transitions that neither reverse a justified precedence nor exceed the horizon:
  S_temp(p) = (1/(m−1)) · Σ 1[c_i], where c_i holds when (s_i = s_{i+1} or s_{i+1} ⊀ s_i) and 0 < Δt_i ≤ T.

- **Contextual coupling** — average strongest shared-entity relation across consecutive steps:
  S_ctx(p) = (1/(m−1)) · Σ τ(e_i, e_{i+1}), τ = 1.0 shared process lineage, 0.6 shared socket/session, 0 otherwise.

Each term ∈ [0,1]. S_temp and S_ctx are defined for m ≥ 2; for m = 1 both are 0.

- **Combined risk:** R(p) = w1·S_seq + w2·S_temp + w3·S_ctx

## 4. Fixed hyperparameters

- Weights: **w1 = 0.5, w2 = 0.3, w3 = 0.2** (alignment prioritized a priori; not tuned).
- Correlation / temporal horizon: **T = 3600 s**.
- Context tiers: lineage 1.0, socket/session 0.6, else 0.
- No learned parameters; scoring is deterministic.

## 5. Telemetry-to-ATT&CK tagging rules (fixed)

Each CDM event is checked against the same frozen behaviour-based rules, applied uniformly to attacker and benign activity; only events satisfying a rule receive a technique.

| Technique / signal | Observable CDM predicate | Guard |
|---|---|---|
| T1190 | public-facing server issues outbound connection to external address | server set; address external |
| T1071.001 | outbound connect/sendto/sendmsg to external address | internal ranges excluded |
| T1105 | write/create of a real file path | exclude /dev, /var/log |
| T1087.001 | read/open of an account file (/etc/passwd, group) | exclude auth readers |
| Discovery (T1057/T1033/T1046/T1016/T1082) | execute of a discovery tool (ps, whoami, netstat, …) | tool in discovery set |
| T1068 (PE stage) | change_principal event | stage level only |
| T1070.004 | unlink of a real file path | exclude \<unknown\> |
| T1620, T1055 | not independently observable in this telemetry | documented, not tagged |

Declared in advance as **not independently observable** in this telemetry: reflective in-memory loading (T1620) and process injection into sshd (T1055). Both remain in R but are reported as unobservable.

## 6. Path construction (fixed)

Events are assembled into candidate paths by following process lineage with file and socket dataflow within T = 3600 s. Stages are projected per matched technique.

## 7. Labelling rule (fixed)

A path is labelled an **attack** only when it contains at least two independently ground-truth-supported malicious behaviours inside a documented attack window (per the DARPA TC Engagement 3 ground-truth report). All other candidate paths are benign.

## 8. Baselines (fixed, declared in advance)

- Path-length baseline (raw number of steps).
- Distinct-technique-count baseline.
- Event-level detector (alert on every rule match, no path aggregation).

## 9. Metrics (fixed)

ROC-AUC and average precision (AP), AP emphasised due to class imbalance. Reported per host. Given the small positive class, AUC is treated as descriptive; uncertainty quantified by a stratified path-level bootstrap.

## 10. Datasets (evaluation targets, not used to set any parameter above)

- DARPA TC Engagement 3 **CADETS** (FreeBSD server, CDM 18).
- DARPA TC Engagement 3 **THEIA** (Ubuntu workstation, CDM 18).

Only dataset-specific telemetry decoding (not scoring) was adapted per host: for THEIA, the acting process is resolved through the subject record and file paths are read from the file object.

## 11. What was NOT part of the fixed design (exploratory)

The inverse-frequency (rarity) reweighting reported in the Discussion is **post-hoc and exploratory**. It uses the same labelling and the same benign population, so its figure is in-sample and not a validated result.
