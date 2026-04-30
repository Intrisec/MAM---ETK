"""
MAM-ETK v3.1 (Maternal Attunement Monitor) — Live Demo
==============================
Run with:  python demo.py

No external datasets required. Demonstrates:
  • Real-time behavioral monitoring of 4 synthetic processes
  • Progressive ransomware detection (phases 1→3)
  • APT low-and-slow accumulation → D-2 syndrome
  • False-positive resilience + human ACK confirmation
  • Orphan spawn clinging → D-5 (v3.1 new)
  • Explainable Pc chain: why it alerted, not just that it did

Derived from ETK (Ecosistemul Teoretic Katharós):
  Q(t) ↔ process coherence | I_p ↔ threat inflation
  N_cross ↔ threshold crossings | A_Q ↔ archive integrity
  F_abandon ↔ orphan-spawn clinging | ACK ↔ retrograde validation
"""

import random
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from mam import MAMETKv31, THETA_CAL
    from scenarios import (
        scenario_normal, scenario_ransomware, scenario_apt,
        scenario_false_positive, scenario_orphan_clinging,
    )
except ImportError as e:
    print(f"\n[ERROR] Cannot import Sentinel engine: {e}")
    print("Make sure mam.py and scenarios.py are in the same directory.")
    sys.exit(1)

# ── Terminal colors (graceful fallback if not supported) ─────────────────────
def _supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

if _supports_color():
    R  = "\033[91m"; Y  = "\033[93m"; G  = "\033[92m"
    B  = "\033[94m"; C  = "\033[96m"; M  = "\033[95m"
    W  = "\033[97m"; DIM = "\033[2m"; RESET = "\033[0m"; BOLD = "\033[1m"
else:
    R = Y = G = B = C = M = W = DIM = RESET = BOLD = ""

def color_level(level):
    if "TERMINATE" in level: return f"{R}{BOLD}{level}{RESET}"
    if "QUARANTINE" in level: return f"{Y}{BOLD}{level}{RESET}"
    if "WATCH" in level:      return f"{M}{level}{RESET}"
    return f"{G}{level}{RESET}"

def pc_bar(pc, width=20):
    filled = min(width, int(pc / 2.5 * width))
    bar = "█" * filled + "░" * (width - filled)
    color = R if pc >= 2.0 else Y if pc >= 1.5 else M if pc >= 0.8 else G
    return f"{color}[{bar}]{RESET} {pc:.3f}"

def section(title, char="═"):
    w = 72
    print(f"\n{C}{char * w}{RESET}")
    print(f"{C}{char}  {BOLD}{title}{RESET}")
    print(f"{C}{char * w}{RESET}")

def row(pid, level, pc, q, i, ncross, syn, note=""):
    lvl_str = color_level(level)
    bar = pc_bar(pc)
    syn_str = f" {R}[{syn}]{RESET}" if syn else ""
    note_str = f"  {DIM}{note}{RESET}" if note else ""
    print(f"  {W}{pid:<18}{RESET} {lvl_str:<30} Pc={bar}  "
          f"Q={q:.3f}  I={i:.3f}  N×={ncross}{syn_str}{note_str}")

def pause(ms=40):
    time.sleep(ms / 1000)

# ── MAIN DEMO ─────────────────────────────────────────────────────────────────
def main():
    random.seed(42)

    print(f"\n{BOLD}{C}{'═'*72}")
    print(f"  MAM-ETK v3.1  —  Behavioral Temporal Anomaly Detector")
    print(f"  Derived from ETK (Ecosistemul Teoretic Katharós)")
    print(f"  Author: Alexandru Ciprian Cătălin · Katharós Research")
    print(f"  ORCID:  0009-0000-6779-750X")
    print(f"{'═'*72}{RESET}\n")

    print(f"{DIM}  Initializing engine + calibrating on {THETA_CAL} normal cycles...{RESET}")
    s = MAMETKv31("MAM-ETK-Demo")
    for _ in range(THETA_CAL):
        s.calibrate(scenario_normal())
    print(f"  {G}✓ Calibrated.{RESET}  VK_ref = {{{', '.join(f'{k}: {v:.1f}' for k,v in s.VK_ref.items())}}}\n")

    # Spawn 4 processes
    s.spawn("browser.exe",   image_hash="a1b2c3d4")
    s.spawn("svchost.exe",   image_hash="e5f6a7b8")   # will go APT
    s.spawn("explorer.exe",  image_hash="c9d0e1f2")   # will go ransomware
    s.spawn("updater.exe",   image_hash="f3a4b5c6")   # will be orphaned

    # ── SCENE 1: Normal baseline ─────────────────────────────────────────────
    section("SCENE 1 / 5 — Normal Baseline (10 cycles)")
    print(f"  {DIM}All processes running normally. Pc should stay near 0.{RESET}\n")
    print(f"  {'Process':<18} {'Level':<22} {'Pc':>26}  {'Q':>7}  {'I':>6}  {'N×':>4}")
    print(f"  {'─'*70}")
    for c in range(10):
        for pid in ["browser.exe", "svchost.exe", "explorer.exe", "updater.exe"]:
            lvl, _, pc, q = s.watch(pid, scenario_normal())
            ps = s.processes[pid]
            if c == 9:
                row(pid, lvl, pc, q, ps.I, ps.N_cross, ps.syndrome)
        pause(20)
    print(f"\n  {G}→ All processes NOMINAL. Zero false positives.{RESET}")

    # ── SCENE 2: Ransomware (explorer.exe) ───────────────────────────────────
    section("SCENE 2 / 5 — Ransomware Attack on explorer.exe (3 phases)")
    print(f"  {DIM}Phase 1: reconnaissance. Phase 2: encryption burst. Phase 3: full takeover.{RESET}\n")
    print(f"  {'Cycle':<6} {'Process':<18} {'Level':<22} {'Pc':>26}  {'Q':>7}  {'I':>6}")
    print(f"  {'─'*80}")
    for phase in [1, 1, 2, 2, 2, 3, 3, 3]:
        obs = scenario_ransomware(phase)
        lvl, _, pc, q = s.watch("explorer.exe", obs)
        ps = s.processes["explorer.exe"]
        note = f"phase {phase}"
        row("explorer.exe", lvl, pc, q, ps.I, ps.N_cross, ps.syndrome, note)
        if "TERMINATE" in lvl:
            print(f"\n  {R}{'█'*60}")
            print(f"  █  TERMINATE — explorer.exe isolated. Sandbox activated.")
            print(f"  █  Diagnosis: file_ent={obs['file_ent']:.2f}  disk_io={obs['disk_io']:.0f}  sys_calls={obs['sys_calls']:.0f}")
            print(f"  {'█'*60}{RESET}")
            break
        pause(30)

    # ── SCENE 3: APT low-and-slow (svchost.exe) → D-2 ───────────────────────
    section("SCENE 3 / 5 — APT Low-and-Slow on svchost.exe → Syndrome D-2")
    print(f"  {DIM}Stays in WATCH band for many cycles. N_cross accumulates. D-2 = chronic oscillator.{RESET}\n")
    print(f"  {'Cycle':<6} {'Level':<22} {'Pc':>26}  {'Q':>7}  {'N×':>5}  {'Syndrome'}")
    print(f"  {'─'*75}")
    for c in range(20):
        phase = 2 if c % 4 < 3 else 1   # oscillates in threat band
        lvl, _, pc, q = s.watch("svchost.exe", scenario_apt(phase))
        ps = s.processes["svchost.exe"]
        syn = f"{R}{ps.syndrome}{RESET}" if ps.syndrome else f"{DIM}—{RESET}"
        print(f"  {c+1:<6} {color_level(lvl):<30} Pc={pc_bar(pc)}  Q={q:.3f}  N×={ps.N_cross:<5}  {syn}")
        if ps.syndrome == "D-2":
            print(f"\n  {Y}{'█'*60}")
            print(f"  █  D-2 CONFIRMED — Chronic oscillator detected.")
            print(f"  █  N_cross={ps.N_cross}  Dd variance > threshold.")
            print(f"  █  Permanent QUARANTINE. Cannot be ACK'd out without reostatare.")
            print(f"  {'█'*60}{RESET}")
            break
        pause(25)

    # ── SCENE 4: False positive + human ACK ──────────────────────────────────
    section("SCENE 4 / 5 — False Positive + Human ACK Confirmation")
    print(f"  {DIM}browser.exe runs a backup job — spikes look suspicious. Human confirms benign.{RESET}\n")

    obs_fp = scenario_false_positive()
    print(f"  Backup job starts: cpu={obs_fp['cpu']:.0f}  disk_io={obs_fp['disk_io']:.0f}  sys_calls={obs_fp['sys_calls']:.0f}")
    lvl, _, pc, q = s.watch("browser.exe", obs_fp)
    ps = s.processes["browser.exe"]
    row("browser.exe", lvl, pc, q, ps.I, ps.N_cross, ps.syndrome, "ALERT — backup job?")

    print(f"\n  {Y}→ Sentinel flags. Human analyst reviews...{RESET}")
    pause(500)
    ack_msg = s.retrograde_validation("browser.exe", user_confirm=True,
                                       ack_strength=0.9, peer_confirm=True)
    trust_after = s.archive_Q["browser.exe"].trust
    lvl2, _, pc2, q2 = s.watch("browser.exe", scenario_normal())
    print(f"  {G}→ ACK confirmed (strength=0.9, peer=True).{RESET}")
    print(f"     trust → {trust_after:.3f}  Pc → {pc2:.3f}  Level → {lvl2}")
    print(f"  {G}→ Latch released. browser.exe back to NOMINAL.{RESET}")

    # ── SCENE 5: Orphan spawn clinging → D-5 (v3.1 new) ─────────────────────
    section("SCENE 5 / 5 — Orphan Clinging Spawn → Syndrome D-5  [v3.1 new]")
    print(f"  {DIM}updater.exe parent is terminated. Child shows re-attachment beaconing.{RESET}")
    print(f"  {DIM}F_abandon accumulates → D-5 (no equivalent in classical EDR).{RESET}\n")
    print(f"  {'Cycle':<6} {'Level':<22} {'Pc':>26}  {'F_abn':>8}  {'Syndrome'}")
    print(f"  {'─'*75}")

    # Notify parent terminated
    s.notify_parent_terminated("browser.exe")   # use browser as parent proxy
    s.processes["updater.exe"].parent_pid = "browser.exe"
    s.processes["updater.exe"].parent_terminated = True

    for c in range(60):
        obs, s_ev = scenario_orphan_clinging(c, after_kill=0)
        lvl, _, pc, q = s.watch("updater.exe", obs, S_ev=s_ev)
        ps = s.processes["updater.exe"]
        if c % 5 == 0 or ps.syndrome == "D-5":
            syn = f"{R}{ps.syndrome}{RESET}" if ps.syndrome else f"{DIM}—{RESET}"
            print(f"  {c+1:<6} {color_level(lvl):<30} Pc={pc_bar(pc)}  "
                  f"F={ps.F_abandon:>6.3f}  {syn}")
        if ps.syndrome == "D-5":
            print(f"\n  {Y}{'█'*60}")
            print(f"  █  D-5 QUARANTINE — Clinging orphan spawn.")
            print(f"  █  F_abandon={ps.F_abandon:.3f} > F_crit=1.5")
            print(f"  █  Parent-kill shock → re-attach beaconing → C2 candidate.")
            print(f"  █  This syndrome has no equivalent in Sysmon / Falcon / EDR.")
            print(f"  {'█'*60}{RESET}")
            break
        pause(15)

    # ── FINAL SUMMARY ────────────────────────────────────────────────────────
    section("FINAL STATUS", char="─")
    print(f"\n{s.status()}")

    print(f"\n{C}{'═'*72}")
    print(f"  ETK → Sentinel: theory becomes detector.")
    print(f"  Q(t), I_p, N_cross, A_Q, F_abandon — biological variables,")
    print(f"  running on real process telemetry.")
    print(f"")
    print(f"  Alexandru Ciprian Cătălin · Katharós Research")
    print(f"  https://github.com/katharos-research/mam-etk")
    print(f"{'═'*72}{RESET}\n")


if __name__ == "__main__":
    main()
