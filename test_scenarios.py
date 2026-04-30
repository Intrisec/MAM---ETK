"""MAM-ETK v3.1 — scenario regression + new v3.1 capability tests.

Includes:
  S01-S10  : v3.0 regression
  S11      : A_Q chronic depletion → irrecoverable flag (N1)
  S12      : F_abandon clinging-spawn after parent kill → D-5 (N3)
  S13      : Weighted ACK in alert storm — storm dampener (N6)
  S14      : Smooth BURON modulation produces continuous FP curve (N2)

Predictions:
  P-SENT-1..5  : v3.0 regression
  P-SENT-6     : A_Q separates "recoverable D-2" from "terminal D-2" (N1)
  P-SENT-7     : Orphan-clinging detector — D-5 fires on parent-kill cohort (N3)
"""
from __future__ import annotations
import os
import random
import statistics
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mam import (
    MAMETKv31, THETA_CAL, PC_QUARANTINE, PC_TERMINATE, LATCH_Q,
    HEP_DISCREPANCY, A_Q_TERMINAL, F_CRIT, F_MAX,
)
from scenarios import (
    BASELINE, scenario_normal, scenario_ransomware, scenario_apt,
    scenario_false_positive, scenario_oscillating_apt, scenario_kernel_spoof,
    scenario_orphan_clinging,
)

random.seed(42)


def fresh(name="S"):
    s = MAMETKv31(name)
    for _ in range(THETA_CAL):
        s.calibrate(scenario_normal())
    return s


def banner(t): print(f"\n{'═'*78}\n  {t}\n{'═'*78}")


# ─── S01–S10 (regression v3.0) ───────────────────────────────────────────────
def s01():
    banner("S01 — Normal baseline (FP < 5%)")
    s = fresh()
    fp = sum(1 for _ in range(200)
             if s.watch("benign", scenario_normal())[0] != "NOMINAL")
    rate = fp / 200
    print(f"  FP rate: {rate:.3f}")
    return rate < 0.05


def s02():
    banner("S02 — Ransomware progressive → TERMINATE")
    s = fresh()
    levels = []
    for ph in [1, 2, 3]:
        for _ in range(5):
            levels.append(s.watch("ransom", scenario_ransomware(ph))[0])
    ok = any("TERMINATE" in l for l in levels)
    print(f"  Reached TERMINATE: {ok}")
    return ok


def s03():
    banner("S03 — APT oscilator → D-2")
    s = fresh()
    last = None
    for c in range(60):
        s.watch("apt-osc", scenario_oscillating_apt(c))
        if s.processes["apt-osc"].syndrome:
            last = s.processes["apt-osc"].syndrome
    print(f"  Last syndrome: {last} | N×={s.processes['apt-osc'].N_cross}")
    return last == "D-2"


def s04():
    banner("S04 — FP + ACK + latch (post-ACK Pc < TERMINATE)")
    s = fresh()
    s.watch("update", scenario_false_positive())
    pre = s.archive_Q["update"].trust
    s.retrograde_validation("update", user_confirm=True, ack_strength=1.0)
    post = s.archive_Q["update"].trust
    s.watch("update", scenario_false_positive())
    lvl, _, pc, _ = s.watch("update", scenario_false_positive())
    ok = post > pre and pc < PC_TERMINATE
    print(f"  trust {pre:.3f}→{post:.3f}  Pc_after={pc:.3f} ({lvl})")
    return ok


def s05():
    banner("S05 — Kernel spoof → D-3")
    s = fresh()
    for _ in range(20):
        true_obs = scenario_ransomware(2)
        userspace, hep = scenario_kernel_spoof(true_obs)
        s.watch("rk", userspace, obs_hep=hep)
        if s.processes["rk"].syndrome == "D-3":
            print("  D-3 triggered: True"); return True
    print("  D-3 triggered: False"); return False


def s06():
    banner("S06 — Supply chain → D-1")
    s = fresh()
    s.spawn("supplier")
    for _ in range(5):
        s.watch("supplier", scenario_ransomware(2))
    for _ in range(3):
        s.retrograde_validation("supplier", user_confirm=False)
    s.spawn("child-app", parent_pid="supplier", image_hash="abc")
    triggered = False
    for _ in range(5):
        s.watch("child-app", scenario_ransomware(3),
                parent_pid="supplier", image_hash="abc")
        if s.processes["child-app"].syndrome == "D-1":
            triggered = True; break
    print(f"  parent trust={s.archive_Q['supplier'].trust:.3f}  D-1={triggered}")
    return triggered


def s07():
    banner("S07 — Resilience paradox → D-4")
    s = fresh()
    s.spawn("trusted-parent"); s.archive_Q["trusted-parent"].trust = 0.95
    s.spawn("resilient", parent_pid="trusted-parent")
    triggered = False
    for c in range(72):
        obs = scenario_apt(3) if c % 12 == 0 else scenario_normal()
        s.watch("resilient", obs, parent_pid="trusted-parent")
        if s.processes["resilient"].syndrome == "D-4":
            triggered = True; break
    ps = s.processes["resilient"]
    print(f"  Q={ps.Q:.3f} Dd={ps.Dd_raw:.3f} N×={ps.N_cross} syn={ps.syndrome}")
    return triggered


def s08():
    banner("S08 — Latch persistence (Q<0.15 needs ACK)")
    s = fresh()
    for _ in range(15):
        s.watch("collapsed", scenario_ransomware(3))
    ps = s.processes["collapsed"]
    latched = ps.latch_active
    for _ in range(50):
        s.watch("collapsed", scenario_normal())
    still = s.processes["collapsed"].latch_active
    s.retrograde_validation("collapsed", user_confirm=True, ack_strength=1.0)
    cleared = not s.processes["collapsed"].latch_active
    print(f"  latch={latched} still_after_50={still} cleared_by_ACK={cleared}")
    return latched and still and cleared


def s09():
    banner("S09 — Trust-pump cap")
    s = fresh()
    s.watch("v", scenario_false_positive())
    init = s.archive_Q["v"].trust
    for _ in range(10):
        s.watch("v", scenario_false_positive())
        s.retrograde_validation("v", user_confirm=True, ack_strength=1.0)
    final = s.archive_Q["v"].trust
    capped = (final - init) <= 0.105
    print(f"  Δtrust={final-init:.3f} (cap=0.10) → {capped}")
    return capped


def s10():
    banner("S10 — Persistence tamper → SAFE-MODE")
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
    try:
        s1 = MAMETKv31("S-p", persistence_path=tmp, hmac_passphrase="k1")
        for _ in range(THETA_CAL): s1.calibrate(scenario_normal())
        s1.spawn("svc"); s1.archive_Q["svc"].trust = 0.85; s1._persist("svc")
        import sqlite3
        con = sqlite3.connect(tmp)
        con.execute("UPDATE archive_q SET mac='deadbeef' WHERE pid='svc'")
        con.commit(); con.close()
        s2 = MAMETKv31("S-p2", persistence_path=tmp, hmac_passphrase="k1")
        ok = s2.safe_mode
        lvl, _, _, _ = s2.watch("svc", scenario_normal())
        print(f"  safe_mode={ok}  watch={lvl}")
        return ok and lvl == "SAFE-MODE"
    finally:
        try: os.unlink(tmp)
        except: pass


# ─── S11–S14 (v3.1 new) ──────────────────────────────────────────────────────
def s11_aq_irrecoverable():
    banner("S11 — A_Q depletion → irrecoverable flag (N1)")
    s = fresh()
    s.spawn("chronic"); s.archive_Q["chronic"].trust = 0.10
    # Sustained low-trust + adverse: depletes A_Q below terminal
    for _ in range(800):
        s.watch("chronic", scenario_apt(3))
    a_q = s.archive_Q["chronic"].A_Q
    irr = s.processes["chronic"].irrecoverable
    print(f"  A_Q={a_q:.4f} (terminal={A_Q_TERMINAL}) irrecoverable={irr}")
    return a_q < A_Q_TERMINAL and irr


def s12_f_abandon_d5():
    banner("S12 — Orphan clinging → D-5 (N3)")
    s = fresh()
    s.spawn("parent"); s.archive_Q["parent"].trust = 0.50
    s.spawn("child", parent_pid="parent")
    # Run normally for 30 cycles
    for c in range(30):
        s.watch("child", scenario_normal(), parent_pid="parent")
    # Kill parent
    s.notify_parent_terminated("parent")
    # 50 more cycles of clinging behavior
    triggered_d5 = False
    for c in range(50):
        obs, s_ev = scenario_orphan_clinging(30 + c, after_kill=0)
        s.watch("child", obs, S_ev=s_ev)
        if s.processes["child"].syndrome == "D-5":
            triggered_d5 = True
            break
    f = s.processes["child"].F_abandon
    print(f"  F_abandon={f:.3f} (F_crit={F_CRIT}) D-5={triggered_d5}")
    return triggered_d5


def s13_storm_dampener():
    banner("S13 — Weighted ACK storm dampener (N6)")
    # Two scenarios: (A) ACK in calm → trust↑↑; (B) ACK in alert storm → trust↑ much smaller
    sA = fresh("calm")
    sA.spawn("a")
    sA.watch("a", scenario_false_positive())
    deltaA = sA.archive_Q["a"].trust
    sA.retrograde_validation("a", user_confirm=True, ack_strength=1.0)
    deltaA = sA.archive_Q["a"].trust - deltaA

    sB = fresh("storm")
    sB.spawn("b")
    # Generate 30 alerts to fill recent_alerts_window
    for _ in range(30):
        sB.watch("b", scenario_false_positive())
    pre = sB.archive_Q["b"].trust
    sB.retrograde_validation("b", user_confirm=True, ack_strength=1.0)
    deltaB = sB.archive_Q["b"].trust - pre

    print(f"  Δtrust calm={deltaA:.4f}  storm={deltaB:.4f}")
    # Storm should give strictly less trust gain, but still positive
    return deltaB < deltaA and deltaB > 0


def s14_buron_smooth_fp():
    banner("S14 — Smooth BURON modulation (no FP cliff at boundary)")
    # Sweep avg_trust across 0.65→0.75 (the old hard boundary at 0.7)
    # FP rate should change continuously, not jump.
    rates = []
    for t_target in [0.60, 0.65, 0.68, 0.70, 0.72, 0.75, 0.80]:
        s = fresh(f"buron-{t_target}")
        s.spawn("p"); s.archive_Q["p"].trust = t_target
        s.t_KR_global = THETA_CAL * 2
        # edge scenario at WATCH boundary
        def edge():
            return {"cpu": random.uniform(45, 55), "disk_io": random.uniform(20, 30),
                    "net_io": random.uniform(15, 22), "file_ent": random.uniform(0.45, 0.55),
                    "sys_calls": random.uniform(400, 600)}
        fp = sum(1 for _ in range(80)
                 if s.watch("p", edge())[0] != "NOMINAL")
        rates.append((t_target, fp / 80))
    print(f"  trust→FP curve: {[(t, round(r,3)) for t,r in rates]}")
    # Smoothness: max abs jump between adjacent points
    diffs = [abs(rates[i+1][1] - rates[i][1]) for i in range(len(rates)-1)]
    print(f"  max neighbor jump: {max(diffs):.3f}")
    return max(diffs) < 0.30


# ─── P-SENT-1..5 (regression) ────────────────────────────────────────────────
def p1():
    banner("P-SENT-1 — Inflation: ping&retreat detected ≤90 cycles")
    s = fresh()
    found = None
    for c in range(150):
        obs = scenario_apt(2) if (c % 30) < 5 else scenario_normal()
        lvl, _, _, _ = s.watch("pr", obs)
        if "QUARANTINE" in lvl or "TERMINATE" in lvl:
            found = c; break
    ok = found is not None and found <= 90
    print(f"  detected at cycle {found}")
    return ok


def p2():
    banner("P-SENT-2 — N_cross: Pc_osc/Pc_const > 2× at N×>5")
    sA = fresh()
    for c in range(40): sA.watch("o", scenario_oscillating_apt(c))
    pc_o = sA.processes["o"].Pc; n = sA.processes["o"].N_cross
    sB = fresh()
    for _ in range(40): sB.watch("c", scenario_apt(1))
    pc_c = sB.processes["c"].Pc
    ratio = pc_o / max(pc_c, 1e-3)
    ok = n > 5 and ratio > 2.0
    print(f"  Pc_osc={pc_o:.3f} N×={n} Pc_const={pc_c:.3f} ratio={ratio:.2f}×")
    return ok


def p3():
    banner("P-SENT-3 — Inheritance: PC_inherit > PC_orphan first cycle")
    s = fresh()
    s.spawn("word.exe")
    for _ in range(8): s.watch("word.exe", scenario_ransomware(2))
    for _ in range(2): s.retrograde_validation("word.exe", user_confirm=False)
    s.spawn("powershell.exe", parent_pid="word.exe")
    _, _, pc_i, _ = s.watch("powershell.exe", scenario_ransomware(3),
                            parent_pid="word.exe")
    s2 = fresh(); s2.spawn("orphan")
    _, _, pc_o, _ = s2.watch("orphan", scenario_ransomware(3))
    print(f"  Pc_inherit={pc_i:.3f}  Pc_orphan={pc_o:.3f}")
    return pc_i > pc_o


def p4():
    banner("P-SENT-4 — HEP D-3 sensitivity ≥90%")
    n = 50; det = 0
    for t in range(n):
        s = fresh(f"t{t}")
        true_obs = scenario_ransomware(random.choice([2, 3]))
        userspace, hep = scenario_kernel_spoof(true_obs)
        for _ in range(5):
            s.watch(f"rk{t}", userspace, obs_hep=hep)
            if s.processes[f"rk{t}"].syndrome == "D-3":
                det += 1; break
    sens = det / n
    print(f"  sensitivity {sens:.2%}")
    return sens >= 0.90


def p5():
    banner("P-SENT-5 — BURON↔FP correlation r ≤ -0.6")
    def edge():
        return {"cpu": random.uniform(45, 55), "disk_io": random.uniform(20, 30),
                "net_io": random.uniform(15, 22), "file_ent": random.uniform(0.45, 0.55),
                "sys_calls": random.uniform(400, 600)}
    pts = []
    for tr in range(12):
        s = fresh(f"b{tr}")
        target = 0.10 + 0.08 * tr
        s.spawn("p0"); s.archive_Q["p0"].trust = target
        s.t_KR_global = THETA_CAL * 2
        fp = sum(1 for _ in range(80) if s.watch("p0", edge())[0] != "NOMINAL")
        pts.append((s._buron_sys(), fp / 80))
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    if statistics.pstdev(xs) > 0 and statistics.pstdev(ys) > 0:
        mx, my = statistics.mean(xs), statistics.mean(ys)
        cov = sum((x-mx)*(y-my) for x, y in zip(xs, ys)) / len(xs)
        r = cov / (statistics.pstdev(xs) * statistics.pstdev(ys))
    else:
        r = 0.0
    print(f"  r={r:.3f}")
    return r <= -0.6


# ─── P-SENT-6,7 (v3.1 new) ───────────────────────────────────────────────────
def p6_aq_separates_recoverable():
    banner("P-SENT-6 — A_Q separates recoverable D-2 from terminal (N1)")
    # A: D-2 oscillator that gets ACKed periodically — A_Q stays > terminal
    sA = fresh("rec")
    sA.spawn("recoverable")
    for c in range(120):
        sA.watch("recoverable", scenario_oscillating_apt(c))
        if c % 20 == 19:
            sA.retrograde_validation("recoverable", user_confirm=True, ack_strength=0.9)
    a_rec = sA.archive_Q["recoverable"].A_Q
    irr_rec = sA.processes["recoverable"].irrecoverable

    # B: D-2 oscillator with no ACK + low trust — A_Q depletes
    sB = fresh("term")
    sB.spawn("terminal"); sB.archive_Q["terminal"].trust = 0.10
    for c in range(800):
        sB.watch("terminal", scenario_apt(3))
    a_term = sB.archive_Q["terminal"].A_Q
    irr_term = sB.processes["terminal"].irrecoverable

    print(f"  Recoverable A_Q={a_rec:.3f} irr={irr_rec}")
    print(f"  Terminal    A_Q={a_term:.3f} irr={irr_term}")
    # P-SENT-6: separation must be clear AND irrecoverable flags differ
    return (a_rec - a_term) > 0.30 and irr_term and not irr_rec


def p7_orphan_clinging_d5():
    banner("P-SENT-7 — Orphan-clinging cohort: D-5 sensitivity ≥80%")
    n = 30; det = 0
    for t in range(n):
        s = fresh(f"oc{t}")
        s.spawn("p"); s.spawn("ch", parent_pid="p")
        for _ in range(20): s.watch("ch", scenario_normal(), parent_pid="p")
        s.notify_parent_terminated("p")
        for c in range(60):
            obs, s_ev = scenario_orphan_clinging(c, after_kill=0)
            s.watch("ch", obs, S_ev=s_ev)
            if s.processes["ch"].syndrome == "D-5":
                det += 1; break
    sens = det / n
    print(f"  D-5 sensitivity {sens:.2%}")
    return sens >= 0.80


# ─── Monte Carlo ─────────────────────────────────────────────────────────────
def mc(n=100):
    banner(f"Monte Carlo — {n} runs benign noise (FP P95)")
    rates = []
    for _ in range(n):
        s = fresh()
        fp = sum(1 for _ in range(100)
                 if s.watch("b", scenario_normal(noise=0.10))[0] != "NOMINAL")
        rates.append(fp / 100)
    p95 = sorted(rates)[int(0.95 * len(rates))]
    print(f"  mean={statistics.mean(rates):.3f}  P95={p95:.3f}")
    return p95 < 0.05


def run_all():
    banner("SENTINEL v3.1 — SCENARIO + PREDICTION SUITE")
    det = [
        ("S01 normal baseline", s01), ("S02 ransomware progressive", s02),
        ("S03 APT oscilator → D-2", s03), ("S04 FP + ACK + latch", s04),
        ("S05 kernel spoof → D-3", s05), ("S06 supply chain → D-1", s06),
        ("S07 resilience paradox D-4", s07), ("S08 latch persistence", s08),
        ("S09 trust-pump cap", s09), ("S10 persistence tamper", s10),
        ("S11 A_Q irrecoverable [N1]", s11_aq_irrecoverable),
        ("S12 orphan clinging → D-5 [N3]", s12_f_abandon_d5),
        ("S13 storm-dampened ACK [N6]", s13_storm_dampener),
        ("S14 BURON smooth (N2)", s14_buron_smooth_fp),
    ]
    pred = [
        ("P-SENT-1 inflation", p1), ("P-SENT-2 N_cross doubling", p2),
        ("P-SENT-3 inheritance", p3), ("P-SENT-4 HEP sensitivity", p4),
        ("P-SENT-5 BURON↔FP", p5),
        ("P-SENT-6 A_Q separates [N1]", p6_aq_separates_recoverable),
        ("P-SENT-7 orphan-clinging D-5 [N3]", p7_orphan_clinging_d5),
    ]
    det_r = [(n, fn()) for n, fn in det]
    pred_r = [(n, fn()) for n, fn in pred]
    mc_ok = mc(100)
    banner("RAPORT FINAL — SCENARIOS + PREDICȚII")
    dp = sum(1 for _, ok in det_r if ok)
    pp = sum(1 for _, ok in pred_r if ok)
    print(f"\n  Scenarii: {dp}/{len(det_r)}")
    for n, ok in det_r: print(f"    [{'PASS' if ok else 'FAIL'}] {n}")
    print(f"\n  Predicții: {pp}/{len(pred_r)}")
    for n, ok in pred_r: print(f"    [{'PASS' if ok else 'FAIL'}] {n}")
    print(f"\n  Monte Carlo: {'PASS' if mc_ok else 'FAIL'}")
    print(f"\n  TOTAL: {dp+pp+(1 if mc_ok else 0)}/{len(det_r)+len(pred_r)+1}")
    print("═" * 78)
    return {"deterministic": det_r, "predictions": pred_r, "mc": mc_ok}


if __name__ == "__main__":
    run_all()
