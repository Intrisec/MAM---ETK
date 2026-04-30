"""Synthetic scenarios for MAM-ETK v3.1 — extends v3.0 with v3.1-specific tests."""
from __future__ import annotations
import random
from typing import Dict, Tuple

BASELINE = {"cpu": 20.0, "disk_io": 5.0, "net_io": 3.0,
            "file_ent": 0.30, "sys_calls": 100.0}


def scenario_normal(noise: float = 0.08) -> Dict[str, float]:
    return {k: v * (1 + random.uniform(-noise, noise)) for k, v in BASELINE.items()}


def scenario_ransomware(phase: int) -> Dict[str, float]:
    if phase == 1: return {"cpu": 25, "disk_io": 8,   "net_io": 5,   "file_ent": 0.35, "sys_calls": 150}
    if phase == 2: return {"cpu": 85, "disk_io": 200, "net_io": 40,  "file_ent": 0.92, "sys_calls": 8000}
    return            {"cpu": 98, "disk_io": 600, "net_io": 80,  "file_ent": 0.99, "sys_calls": 30000}


def scenario_apt(phase: int) -> Dict[str, float]:
    if phase == 1: return {"cpu": 22, "disk_io": 6,   "net_io": 3.5, "file_ent": 0.32, "sys_calls": 110}
    if phase == 2: return {"cpu": 30, "disk_io": 12,  "net_io": 18,  "file_ent": 0.38, "sys_calls": 300}
    return            {"cpu": 45, "disk_io": 80,  "net_io": 120, "file_ent": 0.55, "sys_calls": 2000}


def scenario_false_positive() -> Dict[str, float]:
    return {"cpu": 78, "disk_io": 150, "net_io": 10, "file_ent": 0.40, "sys_calls": 2000}


def scenario_oscillating_apt(cycle: int) -> Dict[str, float]:
    return scenario_apt(2 if (cycle // 3) % 2 == 0 else 1)


def scenario_kernel_spoof(true_obs: Dict[str, float]) -> Tuple[Dict[str, float], Dict[str, float]]:
    return scenario_normal(noise=0.05), true_obs


def scenario_burst(cycle: int) -> Dict[str, float]:
    if cycle % 10 == 0:
        return scenario_apt(3)
    return scenario_normal()


# ── v3.1 specific ────────────────────────────────────────────────────────────
def scenario_persistent_chronic(cycle: int) -> Dict[str, float]:
    """Long-running mid-stress to deplete A_Q over time (N1 test).
    Stays in WATCH band (Dd ~ 0.20-0.30) for hundreds of cycles → trust erodes
    → A_Q drops slowly toward terminal."""
    return scenario_apt(2)


def scenario_orphan_clinging(cycle: int, after_kill: int = 30) -> Tuple[Dict[str, float], float]:
    """N3 — child whose parent was just terminated. Returns (obs, S_ev_inject).

    For the first cycle after parent kill, S_ev is heavily negative (shock).
    Child shows escalating activity (re-attach, beaconing) for ~40 cycles."""
    if cycle < after_kill:
        # Pre-kill: normal
        return scenario_normal(), 0.0
    cycles_post = cycle - after_kill
    if cycles_post == 0:
        s_ev = -0.5  # parent-kill shock (PARENT_KILL_S_EV)
    elif cycles_post < 5:
        s_ev = -0.3  # ongoing distress
    else:
        s_ev = -0.05
    # Re-attach burst: elevated network + sys_calls
    intensity = min(1.0, cycles_post / 20.0)
    obs = {
        "cpu":       BASELINE["cpu"]       * (1 + 0.5 * intensity),
        "disk_io":   BASELINE["disk_io"]   * (1 + 1.0 * intensity),
        "net_io":    BASELINE["net_io"]    * (1 + 4.0 * intensity),
        "file_ent":  BASELINE["file_ent"]  * (1 + 0.3 * intensity),
        "sys_calls": BASELINE["sys_calls"] * (1 + 5.0 * intensity),
    }
    return obs, s_ev
