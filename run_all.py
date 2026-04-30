"""MAM-ETK v3.1 — full validation suite orchestrator.

Run order:
  1. Structural invariants (12 always-on + 7 functional)
  2. Scenario regression (S01-S14) + Predictions (P-SENT-1..7) + MC
  3. Sobol sensitivity (N=128 base → 1152 evals)
  4. CICIDS2017 session-based evaluation (PRIMARY temporal benchmark)
  5. NSL-KDD ROC/AUC (honest diagnostic — point-wise, expected weak)

Dataset acquisition:
  CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
              Place CSVs in ../cicids2017/ or set CICIDS2017_PATH env var.
              If absent: synthetic demo runs automatically.
  NSL-KDD:    Place nsl_kdd_dataset.csv in ../archive (3)/
              If absent: Stage 5 skipped with explicit warning.
"""
from __future__ import annotations
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def section(t):
    print("\n" + "█" * 78)
    print(f"█  {t}")
    print("█" * 78)


def _warn_incomplete(stage: str, reason: str):
    print(f"\n  [WARNING: INCOMPLETE] {stage}")
    print(f"  Reason: {reason}")
    print(f"  Final report will mark this stage as MISSING.")


def main():
    start = time.time()

    # ── STAGE 1 ──────────────────────────────────────────────────────────────
    section("STAGE 1/5 — STRUCTURAL INVARIANTS")
    from test_invariants import run_all as inv_run
    inv = inv_run()
    inv_pass = sum(1 for v in inv.values() if v)
    inv_total = len(inv)

    # ── STAGE 2 ──────────────────────────────────────────────────────────────
    section("STAGE 2/5 — SCENARIOS + PREDICTIONS")
    from test_scenarios import run_all as sc_run
    sc = sc_run()
    sc_pass = (sum(1 for _, ok in sc["deterministic"] if ok)
               + sum(1 for _, ok in sc["predictions"] if ok)
               + (1 if sc["mc"] else 0))
    sc_total = (len(sc["deterministic"]) + len(sc["predictions"]) + 1)

    # ── STAGE 3 ──────────────────────────────────────────────────────────────
    section("STAGE 3/5 — SOBOL SENSITIVITY (N=128, 1152 evals)")
    from sobol_sensitivity import run as sobol_run
    sob = sobol_run(N=128)

    # ── STAGE 4 — CICIDS2017 (PRIMARY) ───────────────────────────────────────
    section("STAGE 4/5 — CICIDS2017 SESSION-BASED (PRIMARY TEMPORAL BENCHMARK)")
    print("  Reference: Sharafaldin, Lashkari & Ghorbani (2018)")
    print("  Primary metric: macro session detection @ 5%FP (MAM native mode)")
    cic_dataset = os.environ.get(
        "CICIDS2017_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cicids2017")
    )
    try:
        from cicids2017_eval import run_auto
        cic = run_auto(dataset_dir=cic_dataset, session_len=50, n_sessions=200)
    except Exception as e:
        _warn_incomplete("STAGE 4 — CICIDS2017", str(e))
        cic = None

    # ── STAGE 5 — NSL-KDD (HONEST DIAGNOSTIC) ────────────────────────────────
    section("STAGE 5/5 — NSL-KDD ROC/AUC (HONEST DIAGNOSTIC — point-wise)")
    print("  Reference: Tavallaee et al. (2009)")
    print("  NOTE: Point-wise AUC ~ 0.5 expected by design (temporal detector).")
    print("  Session-based metrics in Stage 4 are the primary evaluation.")
    try:
        from nsl_kdd_eval import run as kdd_run
        kdd = kdd_run()
    except FileNotFoundError as e:
        _warn_incomplete("STAGE 5 — NSL-KDD", f"Dataset not found: {e}")
        kdd = None

    # ── FINAL REPORT ──────────────────────────────────────────────────────────
    elapsed = time.time() - start
    section(f"FINAL REPORT  (wall-clock {elapsed:.1f}s)")

    ok1 = inv_pass == inv_total
    ok2 = sc_pass == sc_total
    print(f"\n  STAGE 1 — Invariants      {inv_pass}/{inv_total}  {'OK' if ok1 else 'FAILURES'}")
    print(f"  STAGE 2 — Scenarios       {sc_pass}/{sc_total}  {'OK' if ok2 else 'FAILURES'}")

    print(f"  STAGE 3 — Sobol top params (ST>0.05):")
    top = sorted(sob["ST"].items(), key=lambda x: -x[1])
    for name, st in top[:5]:
        print(f"             {name:<14} ST={st:+.4f}")

    # CICIDS2017
    print(f"  STAGE 4 — CICIDS2017 SESSION-BASED (PRIMARY):")
    if cic:
        sb = cic.get("session_based", {})
        print(f"    Macro detection @5%FP : {sb.get('macro_detection_5fp', 0):.3f}")
        print(f"    Macro detection @1%FP : {sb.get('macro_detection_1fp', 0):.3f}")
        for fam, m in sb.get("per_family", {}).items():
            cyc = m.get('mean_detection_cycle', float('nan'))
            cyc_str = f"{cyc:.1f}" if cyc == cyc else "—"
            print(f"      {fam:<20} det@5%={m.get('detection_at_5fp',0):.3f}  "
                  f"det@1%={m.get('detection_at_1fp',0):.3f}  cycle={cyc_str}")
        pw = cic.get("point_wise_auc", {})
        if pw.get("per_family"):
            print(f"    Point-wise AUC (ref): macro={pw.get('macro', 0):.4f}  (weak by design)")
    else:
        print(f"    [MISSING]")

    # NSL-KDD
    print(f"  STAGE 5 — NSL-KDD (HONEST DIAGNOSTIC):")
    if kdd:
        pw = kdd.get("point_wise", {})
        sb5 = kdd.get("session_based", {})
        print(f"    Combined AUC={pw.get('combined_auc', 0):.4f}  "
              f"Macro AUC={pw.get('macro_auc', 0):.4f}  (point-wise, weak expected)")
        print(f"    Session macro @5%FP: {sb5.get('macro_detection_5fp', 0):.3f}")
    else:
        print(f"    [MISSING — dataset not found]")

    print("\n  SUBMISSION CHECKLIST:")
    print(f"    [{'OK' if ok1 else 'FAIL'}] Invariants {inv_pass}/{inv_total}")
    print(f"    [{'OK' if ok2 else 'FAIL'}] Scenarios {sc_pass}/{sc_total}")
    print(f"    [{'OK' if cic else 'MISSING'}] CICIDS2017 evaluation")
    print(f"    [{'OK' if kdd else 'MISSING'}] NSL-KDD honest diagnostic")
    if not cic:
        print("    [!] For publishable metrics: download CICIDS2017 real data")
        print("        https://www.unb.ca/cic/datasets/ids-2017.html")
    print("\n" + "█" * 78)


if __name__ == "__main__":
    main()
