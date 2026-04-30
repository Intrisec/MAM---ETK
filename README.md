# MAM-ETK v3.1

**MAM-ETK — Maternal Attunement Monitor**
**Behavioral Temporal Anomaly Detection Engine**  
*Derived from ETK — Ecosistemul Teoretic Katharós*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![Author ORCID](https://img.shields.io/badge/ORCID-0009--0000--6779--750X-green)](https://orcid.org/0009-0000-6779-750X)
[![Validation](https://img.shields.io/badge/Invariants-19%2F19-brightgreen)]()
[![Scenarios](https://img.shields.io/badge/Scenarios-22%2F22-brightgreen)]()

---

## What is MAM-ETK?

MAM-ETK is a **per-process behavioral anomaly detector** for endpoint security. Unlike classical IDS/EDR systems that classify individual packets or events, MAM monitors each process as a **temporal state machine** — accumulating threat signals over time and detecting patterns invisible to snapshot-based classifiers.

> **Why "Maternal Attunement Monitor"?**  
> Classical IDS names (Sentinel, Guardian, Shield) encode adversarial metaphors — a guard at a gate looking for enemies.  
> MAM-ETK does not look for enemies. It measures systemic excitability, detects deviation from homeostatic baseline, and responds calibrated to context.  
> This is, functionally, maternal regulation: tonic monitoring, perturbation detection, calibrated response.  
> The name is derived directly from ETK, where ε(m), OXTR, and the entire conceptual apparatus derive from the maternal relationship.  
> **MAM is not a defender. MAM is an attentive presence.**


Its architecture is derived from **ETK (Ecosistemul Teoretic Katharós)**, a theoretical neuroscience framework formalizing consciousness, perinatal neurobiology, and attachment dynamics. The same mathematical variables that describe biological threat-response in organisms are mapped, here, to endpoint security primitives.

```
Q(t)      ↔  process behavioral coherence       [0,1]
I_p       ↔  neuroceptive inflation accumulator
N_cross   ↔  threshold traversal counter         (D-2 trigger)
A_Q       ↔  archive integrity (recoverability)  [0,1]
F_abandon ↔  orphan-spawn clinging dynamics      (D-5, new in v3.1)
ACK/L_Q   ↔  retrograde validation (human-in-the-loop confirmation)
```

---

## Run the Demo (no datasets needed)

```bash
git clone https://github.com/katharos-research/mam-etk
cd mam-etk
pip install numpy scipy
python demo.py
```

**What you will see:**

```
SCENE 1 — Normal baseline: 4 processes, zero false positives
SCENE 2 — Ransomware (3 phases): explorer.exe → QUARANTINE → TERMINATE in 5 cycles
SCENE 3 — APT low-and-slow: svchost.exe → N_cross accumulates → D-2 syndrome
SCENE 4 — False positive + human ACK: browser.exe flagged, analyst confirms benign, latch released
SCENE 5 — Orphan clinging (v3.1 new): updater.exe → parent killed → D-5 in 7 cycles
```

---

## Why Different from Classical EDR?

| Capability | Sysmon | Elastic EDR | CrowdStrike Falcon | **MAM-ETK** |
|---|:---:|:---:|:---:|:---:|
| Per-event classification | ✓ | ✓ | ✓ | — |
| Temporal state accumulation | — | partial | partial | ✓ |
| Parent-child risk propagation | — | — | — | ✓ D-5 |
| Archive integrity tracking (A_Q) | — | — | — | ✓ |
| Explainable Pc chain (why, not just that) | — | partial | — | ✓ |
| Human retrograde ACK (weighted) | — | — | — | ✓ |
| Biological derivation (ETK) | — | — | — | ✓ |

**MAM-ETK detects what accumulates over time, not what spikes in a single moment.**

---

## Detection Syndromes

| ID | Trigger | Response | Analog |
|---|---|---|---|
| **D-1** | Parent trust < 0.45 + Pc ≥ TERMINATE | TERMINATE + supply-chain alert | Supply-chain compromise |
| **D-2** | N_cross > 5 + Dd variance > threshold | Permanent QUARANTINE | Chronic oscillator (low-and-slow APT) |
| **D-3** | HEP telemetry discrepancy > 15% | D3-TERMINATE + forensics | Kernel spoof |
| **D-4** | High Q + high Dd + N_cross ≥ 2 | HIGH-TELEMETRY WATCH | Resilience paradox |
| **D-5** | F_abandon > F_crit *(new v3.1)* | D5-QUARANTINE | Orphan clinging spawn → C2 candidate |

---

## Validation Results

### Structural Invariants: 19/19 PASS
Property-based testing across 1000 random cycles (mixed attack/normal scenarios):

- **I1–I12**: Always-on bounds (Q, Dd, I, F, A_Q, trust, Pc, N_cross, trust-pump cap, irrecoverable consistency)
- **F1–F7**: Functional invariants (Pc monotonicity, Q recovery, trust-pump cap, hysteresis asymmetry, A_Q depletion, F_abandon bound, BURON smoothness)

### Scenario Regression: 22/22 PASS

| Category | Count | Result |
|---|---|---|
| Deterministic scenarios (S01–S14) | 14 | ✓ All pass |
| Predictions (P-SENT-1..7) | 7 | ✓ All pass |
| Monte Carlo FP (P95) | 1 | P95 = 0.000 |

### Global Sensitivity (Sobol, N=128, 1152 evals)

Top parameters by total-order index ST:

```
GAMMA_KVS    ST=0.628  ← dominant  (stress amplification gain)
KAPPA        ST=0.355  ← dominant  (C_neuro tanh steepness)
GAMMA_I      ST=0.330  ← dominant  (inflation accumulation rate)
BETA_Q       ST=0.222  ← significant
ALPHA_CROSS  ST=0.221  ← significant
```

### Empirical Evaluation (CICIDS2017, session-based)

Session-based evaluation on CICIDS2017 (Sharafaldin et al. 2018) — MAM-ETK native temporal mode:

| Attack Family | Detection @5%FP | Detection @1%FP | Mean Detection Cycle |
|---|:---:|:---:|:---:|
| DoS | 1.000 | 1.000 | 1.1 |
| PortScan | 1.000 | 1.000 | 11.8 |
| WebAttack | 1.000 | 1.000 | 7.6 |
| Bot | 1.000 | 1.000 | 43.5 |
| **MACRO** | **1.000** | **1.000** | — |

*Bot's mean detection cycle of 43.5 reflects intentional architecture: low-and-slow exfiltration requires temporal accumulation. The cost of near-zero false positives on sustained normal activity is delayed detection of the most subtle threats.*

**Note on point-wise AUC (NSL-KDD):** Point-wise Pc scores yield AUC ≈ 0.5–0.75. This is expected and documented — a temporal detector applied to isolated snapshots loses its signal, for the same reason a heart-rate variability detector appears random on individual beats. Session-based metrics are the meaningful evaluation.

---

## Architecture

```
MAMETKv31
│
├── calibrate(obs)              # build VK_ref from normal baseline
├── spawn(pid, parent_pid)      # register process with optional inheritance
│
├── watch(pid, obs)             # main cycle: neuroception → inflation → state → KVS
│   ├── primary_neuroception()  # Dd_raw, Dd_eff, C_neuro per dimension
│   ├── update_inflation()      # I_p ODE (E-1)
│   ├── update_f_abandon()      # F_abandon ODE (N3, v3.1)
│   ├── update_state()          # Q ODE, N_cross, A_Q, Pc
│   └── kvs_response()          # NOMINAL / WATCH / QUARANTINE / TERMINATE + syndromes
│
├── retrograde_validation()     # weighted ACK: trust + Q bump + storm dampener
├── notify_parent_terminated()  # triggers F_abandon dynamics in children
├── compute_invariants()        # 12 always-on structural checks (N8)
└── reostatare()               # full reset after 50 consecutive clean ACKs
```

---

## ETK — The Theoretical Framework

MAM-ETK is one application of **ETK (Ecosistemul Teoretic Katharós)**, an original theoretical framework developed by Alexandru Ciprian Cătălin (Katharós Research) formalizing:

- Consciousness and perinatal neurobiology
- Epigenetic transmission of attachment patterns (ε(m), OXTR methylation)
- Mathematical modeling of somatic memory (t_KR, A_Q)
- Retrograde confirmation dynamics (ACK/L_Q, nitric oxide, 2-AG)
- The AD causal chain: ACE → ε(m)↑ → TET2↓ → AQP4 delocalized → ALPS↓ → Aβ accumulation

MAM-ETK demonstrates that the ETK formalism is **domain-transferable**: the same equations that model biological attachment resilience also detect behavioral anomalies in computational processes.

*For the full ETK framework, clinical applications, and the primary theoretical documents, contact Katharós Research.*

---

## Repository Structure

```
mam-etk/
├── mam.py          # Core engine — MAMETKv31
├── scenarios.py         # Synthetic attack/normal scenario generators
├── demo.py              # ← Start here. Zero external dependencies.
├── test_invariants.py   # 19 structural invariant tests
├── test_scenarios.py    # 22 scenario + prediction tests
├── sobol_sensitivity.py # Global sensitivity analysis (Sobol/Jansen)
├── nsl_kdd_eval.py      # NSL-KDD honest diagnostic evaluation
├── cicids2017_eval.py   # CICIDS2017 session-based evaluation (primary)
├── run_all.py           # Full validation suite orchestrator
├── requirements.txt     # numpy, scipy
├── CITATION.cff         # Academic citation
└── LICENSE              # MIT
```

---

## Running the Full Validation Suite

```bash
# Quick: invariants + scenarios (no external data needed, ~15s)
python test_invariants.py
python test_scenarios.py

# Full suite including Sobol (no external data, ~3 min)
python run_all.py

# With CICIDS2017 real data (download from UNB):
CICIDS2017_PATH=/path/to/cicids2017/ python run_all.py
```

---

## Requirements

```
Python >= 3.10
numpy  >= 1.24
scipy  >= 1.7   (for Sobol sensitivity analysis only)
```

Standard library only for core engine (`sqlite3`, `hmac`, `json`, `math`, `collections`).

---

## Citation

```bibtex
@software{catalin2026mam,
  author    = {Cătălin, Alexandru Ciprian},
  title     = {MAM-ETK v3.1: Behavioral Temporal Anomaly Detection Engine},
  year      = {2026},
  publisher = {Katharós Research},
  url       = {https://github.com/katharos-research/mam-etk},
  orcid     = {0009-0000-6779-750X}
}
```

---

## License

MIT License — see [LICENSE](LICENSE).

The ETK theoretical framework, clinical methodology, and associated documents remain the intellectual property of Alexandru Ciprian Cătălin / Katharós Research.

---

*MAM-ETK: where biological theory becomes a detector.*  
**Alexandru Ciprian Cătălin · Katharós Research · 2026**
