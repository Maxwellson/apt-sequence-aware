# Sequence-Aware Detection of APT Defense Evasion Using Behavioral Correlation

Reproducibility artifact for the paper *"Sequence-Aware Detection of APT Defense
Evasion Using Behavioral Correlation"*

- **Repository:** https://github.com/ORG/REPO  *(replace with the real URL)*
- **Archived release (DOI):** https://doi.org/10.5281/zenodo.XXXXXXX  *(replace after the Zenodo deposit)*

The method models a host intrusion as a temporal path through an externally
grounded, MITRE ATT&CK–aligned precedence graph and scores each path with three
separable terms (sequence alignment, temporal consistency, contextual coupling).
The scoring design is **frozen**: no weight, horizon, or rule was tuned to the
evaluation data. See `design_specification.md` for the complete fixed design.

## What is here

```
design_specification.md     The frozen design (reference graph, scores, weights,
                            horizon, tagging rules, labelling rule, baselines, metrics).
code/
  scoring.py                Frozen scoring core (R, S_seq, S_temp, S_ctx, risk). No data, no labels.
  make_technique_graph.py   Renders the technique/reference graph figure.
  cadets_e3_inspect.py      CADETS pass 1: streaming structural inspection (no scoring).
  attack_window_probe.py    CADETS probe: real footprint of an attack window.
  attack_link_probe.py      CADETS probe: which relation links the attack steps.
  connector_stage1.py       CADETS tagger (telemetry -> ATT&CK steps, label-independent).
  connector_stage2.py       CADETS pass 2: causal paths -> labels -> frozen scores -> evaluation.
  baseline_eventlevel.py    Event-level ATT&CK baseline (no path aggregation).
  labeling_spec.json        CADETS ground-truth labelling spec.
  theia_e3_probe.py         THEIA calibration probe (encoding + tagger dry run).
  connector_stage1_theia.py THEIA tagger (probe-calibrated).
  connector_stage2_theia.py THEIA pass 2 (same logic as CADETS stage 2).
  labeling_spec_theia.json  THEIA ground-truth labelling spec.
  theia_analyze.py          THEIA results figure/tables from the scored output.
  make_eval_figures.py      Per-component separation + ROC/PR figures from scores_all.csv.
  bootstrap_ci.py           Stratified bootstrap 95% CIs for the CADETS AUCs (paper Sec. IV).
reference/
  R_provenance.csv          Reference precedence graph with per-edge external sources.
  bluedelta_mapping_audit.csv  Motivating-campaign technique mapping audit.
  cadets_e3_attack_mapping.csv Mapping of CADETS attack evidence to techniques.
results/
  scores_all.csv            CADETS per-path scores (derived output; used for figures and CIs).
```

## Requirements

Python 3.10+ and the packages in `requirements.txt`:

```
pip install -r requirements.txt
```

`numpy`, `scipy`, and `matplotlib` are required; `scikit-learn` is optional
(`bootstrap_ci.py` falls back to a rank-based AUC without it).

## Getting the data (not redistributed here)

The raw telemetry is the **DARPA Transparent Computing Engagement 3** CADETS and
THEIA collections (CDM 18), released by DARPA under their own terms. Download them
from the DARPA TC program release:

- https://github.com/darpa-i2o/Transparent-Computing  (Engagement 3 / CDM 18)

Place the decompressed CDM JSON records for each host in its own folder. The
labelling specs (`labeling_spec.json`, `labeling_spec_theia.json`) encode the
attack windows and ground-truth indicators transcribed from the official DARPA TC
Engagement 3 ground-truth report; they do not contain DARPA telemetry.

## Reproducing the results

**CADETS**

```
cd code
python cadets_e3_inspect.py   --folder /path/to/cadets_cdm      # pass 1 (structure)
python connector_stage2.py    --folder /path/to/cadets_cdm      # tag -> paths -> score -> eval
python baseline_eventlevel.py --folder /path/to/cadets_cdm      # event-level baseline
python make_eval_figures.py   ../results/scores_all.csv         # figures
python bootstrap_ci.py        ../results/scores_all.csv         # 95% CIs
```

**THEIA**

```
cd code
python theia_e3_probe.py        --folder /path/to/theia_cdm     # calibration probe
python connector_stage2_theia.py --folder /path/to/theia_cdm    # tag -> paths -> score -> eval
python theia_analyze.py --scores scores_all.csv --summary stage2_summary.json --out .
```

Scoring is deterministic and has no learned parameters, so a given input folder
reproduces the reported values exactly.

## A note on "frozen design"

The design in `design_specification.md` was fixed before scoring attack-labelled
data, and no parameter was tuned to CADETS or THEIA. The inverse-frequency
(rarity) reweighting discussed in the paper is **post-hoc and exploratory**; it is
not part of the frozen design and its reported figure is in-sample.

## Citation

```bibtex
@unpublished{olowononi_maxwellson_apt,
  author = {Olowononi, Felix and Maxwellson, Joshua Enoch},
  title  = {Sequence-Aware Detection of {APT} Defense Evasion Using Behavioral Correlation},
  note   = {Manuscript},
  year   = {2026}
}
```

## License

Code released under the MIT License (see `LICENSE`). The DARPA Transparent
Computing data is subject to DARPA's own terms and is not included here.
