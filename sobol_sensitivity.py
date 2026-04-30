"""Sobol Total-Order Sensitivity Analysis on MAM-ETK v3.1.

Methodology: Saltelli sampling (Saltelli 2002, 2010), bias-corrected
Jansen 1999 estimator for total-order indices ST_i.

Recognized in:
  • Saltelli, A. et al. (2008) "Global Sensitivity Analysis: The Primer"
  • Sobol' (1993) original method
  • SALib library (we re-implement here to avoid dependency)

Output ST_i quantifies the share of model output variance attributable
to parameter i AND all its interactions. ST_i ≈ 0 → parameter inert.
ST_i high → parameter critical.

Parameters under test (7):
  KAPPA, ALPHA_Q, BETA_Q, GAMMA_I, GAMMA_KVS, ALPHA_CROSS, KAPPA_AQ

Output metric: composite_score = TPR_attack - FPR_benign on a fixed
mini-suite (50 cycles attack, 50 cycles benign per eval).

Compute budget: N=128 base samples × (D+2)=9 → 1152 model evals.
"""
from __future__ import annotations
import os
import sys
import numpy as np
from scipy.stats import qmc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mam as eng
from scenarios import scenario_normal, scenario_ransomware


PARAM_BOUNDS = {
    "KAPPA":       (1.0, 4.0),
    "ALPHA_Q":     (0.01, 0.15),
    "BETA_Q":      (0.05, 0.50),
    "GAMMA_I":     (0.01, 0.20),
    "GAMMA_KVS":   (0.0,  1.0),
    "ALPHA_CROSS": (0.0,  0.30),
    "KAPPA_AQ":    (0.5,  2.0),
}
PARAM_NAMES = list(PARAM_BOUNDS.keys())
D = len(PARAM_NAMES)


def model_eval(params: dict, seed: int = 0) -> float:
    """Patch engine constants → run mini-suite → return continuous score.

    Score = mean(Pc on APT phase-2) − mean(Pc on noisy normal).
    APT-2 is in the parameter-sensitive band (Dd ~ 0.15-0.30) where most
    detector parameters matter. Higher score = better separation.
    """
    import random as _r
    from scenarios import scenario_apt
    _r.seed(seed)
    saved = {k: getattr(eng, k) for k in params}
    for k, v in params.items():
        setattr(eng, k, v)
    try:
        s = eng.MAMETKv31("sobol")
        for _ in range(eng.THETA_CAL):
            s.calibrate(scenario_normal())
        if not s.calibrated:
            return 0.0
        # APT phase-2 sustained — Pc grows over time as N_cross / I accumulate.
        s.spawn("att")
        pc_attack = []
        for _ in range(40):
            _, _, pc, _ = s.watch("att", scenario_apt(2))
            pc_attack.append(pc)
        # Edge benign — noisy enough to expose FP-prone configurations.
        s2 = eng.MAMETKv31("sobol-fp")
        for _ in range(eng.THETA_CAL):
            s2.calibrate(scenario_normal())
        if not s2.calibrated:
            return float(np.mean(pc_attack))
        s2.spawn("b")
        pc_benign = []
        for _ in range(40):
            _, _, pc, _ = s2.watch("b", scenario_normal(noise=0.20))
            pc_benign.append(pc)
        return float(np.mean(pc_attack) - np.mean(pc_benign))
    finally:
        for k, v in saved.items():
            setattr(eng, k, v)


def saltelli_matrix(N: int, seed: int = 7) -> np.ndarray:
    """Generate Saltelli matrix of shape (N*(D+2), D) in [0,1]^D."""
    sampler = qmc.Sobol(d=2*D, scramble=True, seed=seed)
    base = sampler.random(N)  # shape (N, 2D)
    A = base[:, :D]
    B = base[:, D:]
    rows = [A, B]
    for i in range(D):
        AB_i = A.copy()
        AB_i[:, i] = B[:, i]
        rows.append(AB_i)
    return np.vstack(rows)  # shape (N*(D+2), D)


def scale(unit_row: np.ndarray) -> dict:
    return {name: PARAM_BOUNDS[name][0] + u * (PARAM_BOUNDS[name][1] - PARAM_BOUNDS[name][0])
            for name, u in zip(PARAM_NAMES, unit_row)}


def sobol_total_order(Y_A: np.ndarray, Y_B: np.ndarray, Y_AB: np.ndarray) -> np.ndarray:
    """Jansen (1999) estimator for ST_i.
       ST_i = (1/(2N)) Σ (Y_A − Y_AB_i)^2 / Var(Y_total)
    """
    var = np.var(np.concatenate([Y_A, Y_B]), ddof=1)
    if var < 1e-12:
        return np.zeros(D)
    ST = np.zeros(D)
    N = len(Y_A)
    for i in range(D):
        ST[i] = np.sum((Y_A - Y_AB[i]) ** 2) / (2 * N) / var
    return ST


def sobol_first_order(Y_A: np.ndarray, Y_B: np.ndarray, Y_AB: np.ndarray) -> np.ndarray:
    """Saltelli 2010 estimator for S1_i."""
    var = np.var(np.concatenate([Y_A, Y_B]), ddof=1)
    if var < 1e-12:
        return np.zeros(D)
    S1 = np.zeros(D)
    N = len(Y_A)
    for i in range(D):
        S1[i] = np.mean(Y_B * (Y_AB[i] - Y_A)) / var
    return S1


def run(N: int = 128, verbose: bool = True):
    print("═" * 78)
    print(f"  SOBOL SENSITIVITY  (N={N} base, D={D}, total evals = {N*(D+2)})")
    print("═" * 78)
    print(f"  Parameters: {PARAM_NAMES}")
    M = saltelli_matrix(N)
    n_total = M.shape[0]

    # Evaluate model for each row
    Y = np.zeros(n_total)
    print(f"  Evaluating {n_total} model runs...")
    for k in range(n_total):
        params = scale(M[k])
        Y[k] = model_eval(params, seed=k)
        if verbose and (k + 1) % max(1, n_total // 10) == 0:
            print(f"    {k+1}/{n_total}  mean={Y[:k+1].mean():+.3f}  std={Y[:k+1].std():.3f}")

    # Slice
    Y_A = Y[:N]
    Y_B = Y[N:2*N]
    Y_AB = [Y[(2+i)*N:(3+i)*N] for i in range(D)]

    ST = sobol_total_order(Y_A, Y_B, Y_AB)
    S1 = sobol_first_order(Y_A, Y_B, Y_AB)

    print("\n  ─── RESULTS ───")
    print(f"  Output Y stats: mean={Y.mean():+.3f}  std={Y.std():.3f}  "
          f"min={Y.min():+.3f}  max={Y.max():+.3f}")
    print(f"\n  {'Parameter':<14} {'S1 (first)':>12} {'ST (total)':>12}  importance")
    print("  " + "─" * 60)
    order = np.argsort(-ST)
    for rank_idx, i in enumerate(order):
        bar = "█" * int(ST[i] * 30) if ST[i] > 0 else ""
        print(f"  {PARAM_NAMES[i]:<14} {S1[i]:>+12.4f} {ST[i]:>+12.4f}  {bar}")
    print("  " + "─" * 60)

    top = [PARAM_NAMES[i] for i in order if ST[i] > 0.05]
    inert = [PARAM_NAMES[i] for i in order if ST[i] < 0.01]
    print(f"\n  TOP (ST>0.05, dominant):  {top}")
    print(f"  INERT (ST<0.01, fixable): {inert}")
    print("═" * 78)
    return {"S1": dict(zip(PARAM_NAMES, S1.tolist())),
            "ST": dict(zip(PARAM_NAMES, ST.tolist())),
            "Y_mean": float(Y.mean()), "Y_std": float(Y.std())}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--N", type=int, default=128, help="Saltelli base samples")
    args = ap.parse_args()
    run(N=args.N)
