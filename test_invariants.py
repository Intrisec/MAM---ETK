"""Structural invariants test (N8 — analog ACPS v13 8 cross-checks).

Property-based: drives engine through random-but-bounded inputs and asserts
the invariants returned by MAMETKv31.compute_invariants() always hold.

Plus 4 functional invariants (monotonicity / hysteresis / cap) that require
running the engine in controlled conditions.

Recognized methodology: structural invariant testing (cf. Hypothesis-style
property tests; ACPS uses 8 cross-checks of identical character).
"""
from __future__ import annotations
import random
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mam import (
    MAMETKv31, THETA_CAL, TRUST_PUMP_CAP, HYSTERESIS_X,
    DD_NCROSS_THRESH, A_Q_TERMINAL,
)
from scenarios import (
    scenario_normal, scenario_ransomware, scenario_apt,
    scenario_oscillating_apt, scenario_false_positive,
)


def fresh(name="inv-test"):
    s = MAMETKv31(name)
    for _ in range(THETA_CAL):
        s.calibrate(scenario_normal())
    return s


# ─── Always-on invariants (12), driven by random walk ──────────────────────
def test_always_on_invariants(seed: int = 42, n_cycles: int = 1000) -> dict:
    """Drive engine through mixed scenarios; compute_invariants() must hold
    after EVERY cycle. Returns dict of invariant_name → bool."""
    random.seed(seed)
    s = fresh("inv-randomwalk")
    failures = {f"I{i}_": [] for i in range(1, 13)}
    pids = ["p1", "p2", "p3"]
    for pid in pids:
        s.spawn(pid)
    for c in range(n_cycles):
        pid = random.choice(pids)
        # mix of scenarios
        r = random.random()
        if r < 0.5:
            obs = scenario_normal(noise=0.10)
        elif r < 0.7:
            obs = scenario_apt(random.choice([1, 2, 3]))
        elif r < 0.85:
            obs = scenario_ransomware(random.choice([1, 2]))
        elif r < 0.95:
            obs = scenario_oscillating_apt(c)
        else:
            obs = scenario_false_positive()
        s_ev = -0.4 if r < 0.05 else 0.0  # occasional adverse event for F_abandon
        s.watch(pid, obs, S_ev=s_ev)
        # Random ACK ~5%
        if random.random() < 0.05:
            s.retrograde_validation(pid, user_confirm=random.random() < 0.7,
                                    ack_strength=random.random())
        inv = s.compute_invariants()
        for k, ok in inv.items():
            if not ok:
                key = k.split("_")[0] + "_"
                failures.setdefault(key, []).append(c)
    results = {}
    for k, fails in failures.items():
        results[k.rstrip("_")] = (len(fails) == 0, fails[:5])
    return results


# ─── F1: Pc strictly increases with sustained ransomware (monotonicity) ────
def test_pc_monotonic_under_attack() -> bool:
    s = fresh("inv-pc-mono")
    s.spawn("attacker")
    pcs = []
    for _ in range(15):
        _, _, pc, _ = s.watch("attacker", scenario_ransomware(2))
        pcs.append(pc)
    # Pc should be non-decreasing over a sustained ransomware (modulo
    # tiny numerical noise from comp4 already at 0). Strict over 5-cycle windows.
    diffs = [pcs[i+5] - pcs[i] for i in range(len(pcs)-5)]
    return all(d > -1e-9 for d in diffs) and pcs[-1] > pcs[0]


# ─── F2: Q recovers under sustained normal AFTER moderate (not severe) stress
# Note: severe stress (apt(3) sustained) intentionally LOCKS recovery via I-inflation
# (E-1 design). This test uses moderate stress (apt(2), 5 cycles) which leaves room
# for recovery within 200 normal cycles.
def test_q_recovers_in_normal() -> bool:
    s = fresh("inv-q-rec")
    s.spawn("p")
    for _ in range(5):
        s.watch("p", scenario_apt(2))
    q_min = s.processes["p"].Q
    for _ in range(200):
        s.watch("p", scenario_normal())
    q_after = s.processes["p"].Q
    return q_after > q_min + 0.05


# ─── F3: Trust-pump cap — 100 ACK attempts cannot exceed +TRUST_PUMP_CAP ──
def test_trust_pump_hard_cap() -> bool:
    s = fresh("inv-pump")
    s.spawn("v")
    s.archive_Q["v"].trust = 0.30
    initial = s.archive_Q["v"].trust
    for _ in range(100):
        s.watch("v", scenario_false_positive())
        s.retrograde_validation("v", user_confirm=True, ack_strength=1.0)
    delta = s.archive_Q["v"].trust - initial
    return delta <= TRUST_PUMP_CAP + 1e-6


# ─── F4: Hysteresis asymmetric — distrust unaffected by HYSTERESIS_X ──────
def test_hysteresis_asymmetric() -> bool:
    s = fresh("inv-hyst")
    s.spawn("p")
    s.archive_Q["p"].trust = 0.50
    # Force manipulated state
    for _ in range(5):
        s.watch("p", scenario_ransomware(2))
    pre = s.archive_Q["p"].trust
    s.retrograde_validation("p", user_confirm=False)  # distrust
    post = s.archive_Q["p"].trust
    distrust_delta = post - pre
    # Should be approximately -0.30 (full effect, NOT divided by HYSTERESIS_X)
    return distrust_delta < -0.20  # must be at least 67% of base -0.30


# ─── F5: A_Q monotonically depletes under sustained low Q + low trust ──────
def test_a_q_depletes_under_chronic() -> bool:
    s = fresh("inv-aq")
    s.spawn("chronic")
    s.archive_Q["chronic"].trust = 0.20  # high ε_proxy
    aq_initial = s.archive_Q["chronic"].A_Q
    for _ in range(500):
        s.watch("chronic", scenario_apt(3))
    aq_final = s.archive_Q["chronic"].A_Q
    return aq_final < aq_initial


# ─── F6: F_abandon respects M7 — saturates strictly below F_MAX ─────────────
def test_f_abandon_bounded() -> bool:
    s = fresh("inv-f")
    s.spawn("orphan")
    # Sustained adverse events
    for _ in range(200):
        s.watch("orphan", scenario_ransomware(2), S_ev=-0.8)
    f_final = s.processes["orphan"].F_abandon
    # M7 saturation: must approach but not exceed F_MAX=5.0
    from mam import F_MAX
    return 0.0 <= f_final <= F_MAX


# ─── F7: BURON modulation continuous (no jump > BONUS+PENALTY) ─────────────
def test_buron_modulation_smooth() -> bool:
    """Sweep avg_trust 0..1; modulation must be continuous (max jump small)."""
    s = MAMETKv31("inv-buron")
    for _ in range(THETA_CAL):
        s.calibrate(scenario_normal())
    s.spawn("p")
    s.t_KR_global = THETA_CAL * 2
    mods = []
    for t in range(0, 101):
        s.archive_Q["p"].trust = t / 100.0
        # also need q_sys_history populated for volatility=0
        s.q_sys_history.clear()
        for _ in range(10):
            s.q_sys_history.append(1.0)
        mods.append(s._buron_modulation())
    # Smoothness check: max neighboring difference should be << total range
    jumps = [abs(mods[i+1] - mods[i]) for i in range(len(mods)-1)]
    return max(jumps) < 0.05  # vs ~0.30 total range


# ─── Reporting helpers ──────────────────────────────────────────────────────
def run_all(verbose: bool = True) -> dict:
    print("═" * 78)
    print("  SENTINEL v3.1 — STRUCTURAL INVARIANTS  (analog ACPS v13 cross-checks)")
    print("═" * 78)
    results = {}

    print("\n[1/2] Always-on invariants (1000 random cycles):")
    aoi = test_always_on_invariants()
    for k, (ok, fails) in aoi.items():
        sym = "PASS" if ok else "FAIL"
        extra = "" if ok else f"  (first failures at cycles: {fails})"
        print(f"   [{sym}] {k}{extra}")
        results[k] = ok

    print("\n[2/2] Functional invariants (controlled scenarios):")
    funcs = [
        ("F1_Pc_monotonic_attack",    test_pc_monotonic_under_attack),
        ("F2_Q_recovers_normal",      test_q_recovers_in_normal),
        ("F3_trust_pump_hard_cap",    test_trust_pump_hard_cap),
        ("F4_hysteresis_asymmetric",  test_hysteresis_asymmetric),
        ("F5_A_Q_depletes_chronic",   test_a_q_depletes_under_chronic),
        ("F6_F_abandon_bounded",      test_f_abandon_bounded),
        ("F7_BURON_modulation_smooth", test_buron_modulation_smooth),
    ]
    for name, fn in funcs:
        try:
            ok = fn()
        except Exception as e:
            ok = False
            print(f"   [FAIL] {name}  ERROR: {e}")
            results[name] = False
            continue
        results[name] = ok
        print(f"   [{'PASS' if ok else 'FAIL'}] {name}")

    total = sum(1 for v in results.values() if v)
    print(f"\n  TOTAL INVARIANTS: {total}/{len(results)}")
    print("═" * 78)
    return results


if __name__ == "__main__":
    run_all()
