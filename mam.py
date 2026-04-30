"""
MAM-ETK v3.1 — clean rebuild aligned with ACPS v13
================================================================================
Architecture:  ACPS v13 / TVKNM v2.3 / NP_Depresia v5 / TUM v3 / TDSAF v4 / Qualia_Q v5
Author:        Alexandru Ciprian Cătălin · Katharós Research
ORCID:         0009-0000-6779-750X

Difference from v3.0 (22 Apr 2026):
  +N1  A_Q dynamics (ACPS v13 Eq.51) — archive integrity ODE, separate from trust
  +N3  F_abandon dynamics (ACPS v13 Op.7, M7) — clinging-spawn detection (D-5)
  +N6  Weighted ACK (signal quality + storm dampener + optional peer channel)
  +N2  Smooth σ on BURON modulation boundary (replace hard 0.3/0.7 step)
  +N8  Public compute_invariants() — 12 structural cross-checks always callable
  +    LIMITATIONS register (analog ACPS v13 L33-L37)

Carries forward unchanged from v3.0:
  E-1 inflation I_p, E-2 N_cross+α_cross, E-3 latch Q<0.15, E-4 reostatare gated,
  E-5 BURON_sys, E-6 HEP discrepancy → D-3, E-7 parent→child inheritance,
  E-8 syndromes D-1..D-4, E-9 U1 chain, E-10 hooks, E-11 timescale,
  E-12 SQLite+HMAC persistence, §3.1 sanity-check, §3.3 trust-pump cap,
  §3.5 Q per-process, asymmetric hysteresis on re-trust only.

MAM_TIMESCALE_NOTE:
  1 cycle = 1 second wall-clock polling. α_Q, β_Q, γ_I calibrated for
  τ_recovery_Q ≈ 20 s at C_neuro=0. Re-scale proportionally if rate changes.
================================================================================
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import math
import os
import random
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ─── ACPS canonical parameters ──────────────────────────────────────────────
KAPPA          = 2.0
ALPHA_Q        = 0.05
BETA_Q         = 0.20
DD_COLLAPSE      = 0.70
DD_NCROSS_THRESH = 0.15
THETA_CAL        = 300
PC_WATCH         = 0.80
PC_QUARANTINE    = 1.50
PC_TERMINATE     = 2.00
HYSTERESIS_X     = 10

# E-1 inflation
GAMMA_I          = 0.05
DELTA_I          = 0.02
DELTA_I_BASE     = 0.015
I_BASAL          = 0.10
I_MAX            = 1.0
GAMMA_KVS        = 0.30
BETA_THETA       = 1.5
C_NEURO_INFLATE_THRESH = 0.10

# E-2 crossings
ALPHA_CROSS      = 0.08
ALPHA_INT        = 0.05

# E-3 latch
LATCH_Q          = 0.15

# E-4 reostatare
REOSTATARE_N_ACKS = 50
REOSTATARE_LAMBDA = 0.05

# E-5 BURON (smooth in v3.1; see _buron_modulation())
BURON_HIGH_BONUS  = 0.20
BURON_LOW_PENALTY = 0.10
BURON_SOFT_K      = 8.0     # σ steepness (N2)

# E-6 HEP
HEP_DISCREPANCY  = 0.15

# E-7 inheritance
INHERIT_TRUST_W    = 0.50
INHERIT_I_FRACTION = 0.30

# E-8 syndromes
D2_NCROSS_MIN  = 5
D2_VARDD_MIN   = 0.005
D4_Q_MIN       = 0.70
D4_DD_MIN      = 0.50

# §3.3 trust-pump cap
TRUST_PUMP_WINDOW = 86400
TRUST_PUMP_CAP    = 0.10

# §3.1 calibration sanity
CAL_VAR_MAX_REL = 0.50

# N1 — A_Q dynamics (ACPS v13 Eq.51)
ALPHA_AQ       = 0.01     # archive population rate (Cat C, uncalibrated — L_v31_1)
DELTA_AQ       = 0.005    # archive depletion rate (Cat C — L_v31_1)
KAPPA_AQ       = 1.0      # OXTR-analog decay coefficient
A_Q_TERMINAL   = 0.05     # past-redemption threshold (analog terminal flatline)

# N3 — F_abandon dynamics (ACPS v13 Eq.21f corrected M7)
ALPHA_F        = 0.30
DELTA_F        = 0.05
F_MAX          = 5.0
F_CRIT         = 1.5      # syndrome D-5 trigger
F_DECAY_BASE   = 0.005    # passive decay even without Q
PARENT_KILL_S_EV = -0.5   # signed event: parent terminated → child shock

# N6 — Weighted ACK
ACK_BASE_TRUST_DELTA = 0.20
ACK_BASE_DISTRUST    = -0.30
ACK_BASE_Q_BUMP      = 0.15
ACK_PEER_BONUS       = 0.5   # 1 + 0.5 multiplier when peer confirms
ACK_STORM_K          = 0.05  # storm dampener slope

# N8 history windows
DD_HISTORY_WIN = 30
U1_HISTORY_WIN = 30
ACK_STORM_WIN  = 60

# Per-dimension max deviation (E-10: empirically calibrated against NSL-KDD
# in nsl_kdd_eval.py; defaults are operating point for synthetic scenarios).
DIM_MAX_DEV = {
    "cpu":       5.0,
    "disk_io":   20.0,
    "net_io":    15.0,
    "file_ent":  3.5,
    "sys_calls": 50.0,
}

WEIGHTS = {
    "cpu":       0.25,
    "disk_io":   0.25,
    "net_io":    0.20,
    "file_ent":  0.20,
    "sys_calls": 0.10,
}

# ── LIMITATIONS register (analog ACPS v13 L33-L37) ──────────────────────────
LIMITATIONS_v3_1 = [
    ("L_v31_1", "α_AQ, δ_AQ Cat C — uncalibrated empirically (analog ACPS L36)"),
    ("L_v31_2", "α_F, δ_F, F_max scalate pentru cyber, neacalibrate pe trace real"),
    ("L_v31_3", "BURON σ-soft transition: k=8 fixed, nu Sobol-tested"),
    ("L_v31_4", "Peer ACK channel: API present, infrastructura distribuită nu"),
    ("L_v31_5", "DIM_MAX_DEV calibrate doar pe NSL-KDD; alte trace pot diferi"),
    ("L_v31_6", "Reostatare empiric netestată (necesită 50 ACK consecutivi)"),
    ("L_v31_7", "F_abandon trigger via S_ev: only parent-kill explicit; alte forme"
                " de adverse-event (resource starvation, signal flood) need mapping"),
]


# ─── ARCHIVE Q ──────────────────────────────────────────────────────────────
@dataclass
class ArchiveQ:
    """Per-process relational somatic memory. ACPS §4.1.1.

    v3.1: A_Q (archive integrity) is a separate state from trust.
    trust  ∈ [0,1] = current relational confidence (Pc input)
    A_Q    ∈ [0,1] = cumulative archive integrity (recoverability)
    """
    trust: float        = 0.50
    A_Q: float          = 1.0          # N1 — ACPS v13 Eq.51
    n_validations: int  = 0
    n_alerts: int       = 0
    n_acks_consec: int  = 0
    manipulated: bool   = False
    t_KR: float         = 0.0
    history: List[str]  = field(default_factory=list)
    trust_deltas_window: List[Tuple[float, float]] = field(default_factory=list)

    def _purge_window(self, now: float):
        cutoff = now - TRUST_PUMP_WINDOW
        self.trust_deltas_window = [(t, d) for (t, d) in self.trust_deltas_window if t >= cutoff]

    def _window_sum_positive(self, now: float) -> float:
        self._purge_window(now)
        return sum(d for (_, d) in self.trust_deltas_window if d > 0)

    def update_trust(self, delta: float, now: float, manipulated: bool = False) -> float:
        """Returns the actual delta applied. Hysteresis only on re-trust (delta>0)."""
        if manipulated:
            self.manipulated = True
            if delta > 0:
                delta /= HYSTERESIS_X
            self.n_acks_consec = 0
        if delta > 0:
            available = max(0.0, TRUST_PUMP_CAP - self._window_sum_positive(now))
            delta = min(delta, available)
            if delta > 0:
                self.n_validations += 1
                self.n_acks_consec += 1
                self.trust_deltas_window.append((now, delta))
        else:
            self.n_acks_consec = 0
            self.trust_deltas_window.append((now, delta))
        self.trust = max(0.0, min(1.0, self.trust + delta))
        return delta

    def update_A_Q(self, Q: float, dt: float = 1.0):
        """N1 — ACPS v13 Eq.51. ε_proxy = 1 - trust (cyber analog of OXTR blockade)."""
        eps = 1.0 - self.trust
        OXTR_avail = math.exp(-KAPPA_AQ * eps)
        dA = ALPHA_AQ * Q * OXTR_avail - DELTA_AQ * (1.0 - Q) * self.A_Q
        self.A_Q = max(0.0, min(1.0, self.A_Q + dA * dt))


# ─── PROCESS STATE ──────────────────────────────────────────────────────────
@dataclass
class ProcessState:
    """All per-process state (§3.5: Q is no longer global)."""
    pid: str
    parent_pid: Optional[str] = None
    image_hash: Optional[str] = None
    Q: float            = 1.0
    I: float            = 0.0
    Dd_raw: float       = 0.0
    Dd_eff: float       = 0.0
    C_neuro: float      = 0.0
    Pc: float           = 0.0
    N_cross: int        = 0
    int_dd_excess: float = 0.0
    above_dd_collapse: bool = False
    latch_active: bool  = False
    irrecoverable: bool = False           # N1 — A_Q < terminal AND Q < latch
    F_abandon: float    = 0.0             # N3 — clinging-spawn accumulator
    S_ev: float         = 0.0             # signed event delta (negative = adverse)
    parent_terminated: bool = False       # N3 — gates F_abandon trigger
    dim_scores: Dict[str, float] = field(default_factory=dict)
    dd_history: collections.deque = field(default_factory=lambda: collections.deque(maxlen=DD_HISTORY_WIN))
    dim_history: collections.deque = field(default_factory=lambda: collections.deque(maxlen=U1_HISTORY_WIN))
    first_alert_cycle: Optional[int] = None
    syndrome: Optional[str] = None
    kvs_level: str = "NOMINAL"
    Dd_hep: float = 0.0
    hep_discrepancy: float = 0.0


# ─── PERSISTENCE LAYER (E-12) ───────────────────────────────────────────────
class PersistenceStore:
    """SQLite + HMAC for Archive Q. v3.1: persists A_Q in addition to trust."""

    def __init__(self, path: str, key: bytes):
        self.path = path
        self.key = key
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(self.path)
        con.execute("""CREATE TABLE IF NOT EXISTS archive_q (
            pid TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            mac  TEXT NOT NULL
        )""")
        con.commit()
        con.close()

    def _mac(self, payload: str) -> str:
        return hmac.new(self.key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def save(self, pid: str, archive: ArchiveQ):
        snap = {
            "trust": archive.trust,
            "A_Q": archive.A_Q,
            "n_validations": archive.n_validations,
            "n_alerts": archive.n_alerts,
            "n_acks_consec": archive.n_acks_consec,
            "manipulated": archive.manipulated,
            "t_KR": archive.t_KR,
            "history_tail": archive.history[-50:],
        }
        payload = json.dumps(snap, sort_keys=True)
        mac = self._mac(payload)
        con = sqlite3.connect(self.path)
        con.execute("INSERT OR REPLACE INTO archive_q(pid,data,mac) VALUES(?,?,?)",
                    (pid, payload, mac))
        con.commit()
        con.close()

    def load_all(self) -> Tuple[Dict[str, ArchiveQ], List[str]]:
        archives: Dict[str, ArchiveQ] = {}
        tampered: List[str] = []
        con = sqlite3.connect(self.path)
        cur = con.execute("SELECT pid, data, mac FROM archive_q")
        for pid, payload, mac in cur:
            if not hmac.compare_digest(mac, self._mac(payload)):
                tampered.append(pid)
                continue
            d = json.loads(payload)
            arch = ArchiveQ(
                trust=d["trust"],
                A_Q=d.get("A_Q", 1.0),
                n_validations=d["n_validations"],
                n_alerts=d["n_alerts"],
                n_acks_consec=d.get("n_acks_consec", 0),
                manipulated=d["manipulated"],
                t_KR=d["t_KR"],
                history=d.get("history_tail", []),
            )
            archives[pid] = arch
        con.close()
        return archives, tampered


def derive_key(passphrase: Optional[str] = None) -> bytes:
    pp = passphrase or os.environ.get("MAM_HMAC_KEY", "default-research-key-30apr2026")
    return hashlib.sha256(pp.encode("utf-8")).digest()


# ─── MAM ENGINE ────────────────────────────────────────────────────────
class MAMETKv31:
    """v3.1 — clean rebuild + ACPS v13 alignment.

    Public surface:
        calibrate(obs)
        spawn(pid, parent_pid=, image_hash=)
        watch(pid, obs, obs_hep=, parent_pid=, image_hash=, S_ev=)
        retrograde_validation(pid, user_confirm, ack_strength=, peer_confirm=)
        notify_parent_terminated(parent_pid)         # N3 trigger
        reostatare(recent_obs, require_acks=)
        compute_invariants() -> Dict[str, bool]      # N8 — always callable
        status() -> str
    """

    # -------------------------------------------------------------------- init
    def __init__(self, name: str = "MAM-ETK-v3.1",
                 persistence_path: Optional[str] = None,
                 hmac_passphrase: Optional[str] = None):
        self.name = name
        self.cycle = 0
        self.t_KR_global = 0.0
        self.VK_ref: Dict[str, float] = {}
        self.cal_buffer: List[Dict] = []
        self.calibrated = False
        self.archive_Q: Dict[str, ArchiveQ] = {}
        self.processes: Dict[str, ProcessState] = {}
        self.event_log: List[str] = []
        self.alerts_u1: List[Dict[str, Any]] = []
        self.recent_alerts_window: collections.deque = collections.deque(maxlen=ACK_STORM_WIN)
        self.safe_mode = False
        self.q_sys_history: collections.deque = collections.deque(maxlen=60)
        self.persistence: Optional[PersistenceStore] = None
        if persistence_path:
            self._init_persistence(persistence_path, hmac_passphrase)

    def _init_persistence(self, path: str, passphrase: Optional[str]):
        self.persistence = PersistenceStore(path, derive_key(passphrase))
        archives, tampered = self.persistence.load_all()
        if tampered:
            self.safe_mode = True
            self._log(f"[D-3-SYS] Persistence tampered for {len(tampered)} pids → SAFE MODE")
        self.archive_Q.update(archives)

    def _persist(self, pid: str):
        if self.persistence:
            self.persistence.save(pid, self.archive_Q[pid])

    # ------------------------------------------------------------- calibration
    def calibrate(self, obs: Dict[str, float]) -> bool:
        self.cal_buffer.append(obs)
        if len(self.cal_buffer) >= THETA_CAL:
            for key in self.cal_buffer[0]:
                vals = [o[key] for o in self.cal_buffer if key in o]
                m = sum(vals) / len(vals)
                if abs(m) < 1e-9:
                    continue
                v = sum((x - m) ** 2 for x in vals) / len(vals)
                rel = math.sqrt(v) / abs(m)
                if rel > CAL_VAR_MAX_REL:
                    self._log(f"[CAL-REJECT] dim={key} relstd={rel:.3f}>{CAL_VAR_MAX_REL}")
                    self.cal_buffer = []
                    return False
            self.VK_ref = {key: sum(o[key] for o in self.cal_buffer) / len(self.cal_buffer)
                           for key in self.cal_buffer[0]}
            self.calibrated = True
            self.t_KR_global = max(self.t_KR_global, float(THETA_CAL))
            self._log(f"[CAL-OK] VK_ref={self.VK_ref}")
        return self.calibrated

    def reostatare(self, recent_obs: List[Dict[str, float]],
                   require_acks: int = REOSTATARE_N_ACKS) -> bool:
        if not self.archive_Q:
            return False
        avg_trust = sum(a.trust for a in self.archive_Q.values()) / len(self.archive_Q)
        total_acks = sum(a.n_acks_consec for a in self.archive_Q.values())
        if avg_trust < 0.7 or total_acks < require_acks:
            self._log(f"[REOSTATARE-DENY] avg_trust={avg_trust:.2f} acks={total_acks}/{require_acks}")
            return False
        if not recent_obs:
            return False
        new_ref = {key: sum(o[key] for o in recent_obs) / len(recent_obs)
                   for key in recent_obs[0]}
        for k in self.VK_ref:
            self.VK_ref[k] = ((1 - REOSTATARE_LAMBDA) * self.VK_ref[k]
                              + REOSTATARE_LAMBDA * new_ref.get(k, self.VK_ref[k]))
        self._log(f"[REOSTATARE-OK] λ={REOSTATARE_LAMBDA}")
        return True

    # -------------------------------------------------------------------- spawn
    def spawn(self, child_pid: str, parent_pid: Optional[str] = None,
              image_hash: Optional[str] = None) -> ProcessState:
        ps = ProcessState(pid=child_pid, parent_pid=parent_pid, image_hash=image_hash)
        if parent_pid and parent_pid in self.archive_Q:
            parent_arch = self.archive_Q[parent_pid]
            child_trust = INHERIT_TRUST_W * 0.5 + (1 - INHERIT_TRUST_W) * parent_arch.trust
            self.archive_Q[child_pid] = ArchiveQ(trust=child_trust)
            if parent_pid in self.processes:
                ps.I = INHERIT_I_FRACTION * self.processes[parent_pid].I
            self._log(f"[SPAWN] {child_pid} ← {parent_pid} | trust={child_trust:.3f} I0={ps.I:.3f}")
        else:
            self.archive_Q.setdefault(child_pid, ArchiveQ())
        self.processes[child_pid] = ps
        return ps

    def _ensure_process(self, pid: str) -> ProcessState:
        if pid not in self.processes:
            self.spawn(pid)
        return self.processes[pid]

    def notify_parent_terminated(self, parent_pid: str):
        """N3 — Inject S_ev shock into all children of a terminated parent."""
        affected = 0
        for pid, ps in self.processes.items():
            if ps.parent_pid == parent_pid:
                ps.parent_terminated = True
                ps.S_ev += PARENT_KILL_S_EV
                affected += 1
        if affected:
            self._log(f"[PARENT-TERM] {parent_pid} → {affected} children kicked (S_ev<<0)")

    # --------------------------------------------------------- L1 neuroception
    def primary_neuroception(self, ps: ProcessState,
                             obs: Dict[str, float],
                             obs_hep: Optional[Dict[str, float]] = None) -> float:
        if not self.VK_ref:
            return 0.0
        sq, sq_hep = 0.0, 0.0
        ps.dim_scores = {}
        for dim, w in WEIGHTS.items():
            ref = max(self.VK_ref.get(dim, 1.0), 1e-6)
            max_dev = DIM_MAX_DEV.get(dim, 10.0)
            val = obs.get(dim, ref)
            rel = (val - ref) / ref
            norm = math.tanh(abs(rel) / max_dev)
            ps.dim_scores[dim] = norm
            sq += w * norm ** 2
            if obs_hep is not None:
                vh = obs_hep.get(dim, ref)
                relh = (vh - ref) / ref
                normh = math.tanh(abs(relh) / max_dev)
                sq_hep += w * normh ** 2
        ps.Dd_raw = math.sqrt(sq)
        ps.Dd_eff = min(1.0, ps.Dd_raw + GAMMA_KVS * ps.I)
        ps.C_neuro = math.tanh(KAPPA * ps.Dd_eff)
        ps.dd_history.append(ps.Dd_raw)
        ps.dim_history.append(dict(ps.dim_scores))
        if obs_hep is not None:
            ps.Dd_hep = math.sqrt(sq_hep)
            denom = max(ps.Dd_raw, 1e-3)
            ps.hep_discrepancy = abs(ps.Dd_raw - ps.Dd_hep) / denom
        else:
            ps.Dd_hep = 0.0
            ps.hep_discrepancy = 0.0
        return ps.C_neuro

    # ------------------------------------------------------- E-1 inflation I_p
    def update_inflation(self, ps: ProcessState, dt: float = 1.0):
        if ps.C_neuro > C_NEURO_INFLATE_THRESH:
            V = 1.0 - ps.C_neuro
            gain = (GAMMA_I * (1 - V) * (1 + 2 * abs(V - 0.5))
                    * (1 - ps.I / I_MAX))
        else:
            gain = 0.0
        V = 1.0 - ps.C_neuro
        decay = (DELTA_I * ps.I * ps.Q
                 + DELTA_I_BASE * max(0.0, ps.I - I_BASAL) * V)
        ps.I = max(0.0, min(I_MAX, ps.I + (gain - decay) * dt))

    # ------------------------------- N3 — F_abandon dynamics (ACPS v13 Op.7 M7)
    def update_f_abandon(self, ps: ProcessState, dt: float = 1.0):
        """dF/dt = α_F·unsafety·|S_ev|·σ(−S_ev,0,10)·(1−F/F_max) − δ_F·F·Q.

        unsafety = 1 - V_composite, where V_composite combines own C_neuro
        with parent-presence (clinical V = perceived caregiver safety):
          V_composite = (1 − C_neuro) · parent_health
          parent_health = 1.0 if no parent
                          parent.trust if parent alive
                          0.0 if parent terminated

        S_ev decays each cycle (event impulse fades).
        """
        if ps.parent_pid is None:
            parent_health = 1.0
        elif ps.parent_terminated:
            parent_health = 0.0
        else:
            parent_arch = self.archive_Q.get(ps.parent_pid)
            parent_health = parent_arch.trust if parent_arch else 1.0
        V_composite = (1.0 - ps.C_neuro) * parent_health
        unsafety = 1.0 - V_composite

        s = ps.S_ev
        smooth_indicator = 1.0 / (1.0 + math.exp(10.0 * s))   # σ(−s,0,10)
        gain = (ALPHA_F * unsafety * abs(s) * smooth_indicator
                * (1.0 - ps.F_abandon / F_MAX))
        decay = DELTA_F * ps.F_abandon * ps.Q + F_DECAY_BASE * ps.F_abandon
        ps.F_abandon = max(0.0, min(F_MAX, ps.F_abandon + (gain - decay) * dt))
        # Event impulse decay (S_ev → 0); slowed for orphans (sustained loss)
        ps.S_ev *= 0.92 if ps.parent_terminated else 0.85

    # ------------------------------------------------------- L2 state evaluation
    def update_state(self, ps: ProcessState, dt: float = 1.0) -> float:
        currently_above = ps.Dd_raw > DD_NCROSS_THRESH
        if currently_above and not ps.above_dd_collapse:
            ps.N_cross += 1
        ps.above_dd_collapse = currently_above
        ps.int_dd_excess += max(0.0, ps.Dd_raw - DD_NCROSS_THRESH) * dt

        alpha_eff = ALPHA_Q / (1.0 + BETA_THETA * ps.I)
        dQ = (alpha_eff * (1 - ps.Q) * (1 - ps.C_neuro)
              - BETA_Q * ps.C_neuro * ps.Q)
        ps.Q = max(0.0, min(1.0, ps.Q + dQ * dt))

        if ps.C_neuro < 0.15:
            self.t_KR_global += dt
            arch = self.archive_Q.setdefault(ps.pid, ArchiveQ())
            arch.t_KR += dt

        # N1 — A_Q evolves every cycle
        arch = self.archive_Q.setdefault(ps.pid, ArchiveQ())
        arch.update_A_Q(ps.Q, dt=dt)

        cal_ratio = min(self.t_KR_global / THETA_CAL, 1.0)
        comp1 = ps.Dd_eff / DD_COLLAPSE
        comp2 = 1.0 - ps.Q
        comp3 = 0.5 * (1.0 - arch.trust)
        comp4 = 0.5 * max(0.0, 1.0 - cal_ratio)
        cross_term = ALPHA_CROSS * ps.N_cross + ALPHA_INT * ps.int_dd_excess
        ps.Pc = comp1 + comp2 + comp3 + comp4 + cross_term

        if ps.Q < LATCH_Q:
            ps.latch_active = True

        # N1 — irrecoverable flag (past redemption)
        if arch.A_Q < A_Q_TERMINAL and ps.Q < LATCH_Q:
            ps.irrecoverable = True
        return ps.Pc

    # ------------------------------------------- E-8 syndrome detection (+ D-5)
    def detect_syndrome(self, ps: ProcessState) -> Optional[str]:
        if ps.hep_discrepancy > HEP_DISCREPANCY:
            return "D-3"
        if (ps.parent_pid and ps.Pc > PC_TERMINATE and ps.Dd_eff > 0.90
                and ps.Q > 0.30):
            parent_arch = self.archive_Q.get(ps.parent_pid)
            if parent_arch and parent_arch.trust < 0.45:
                return "D-1"
        # N3 — D-5: clinging spawn (F_abandon > F_crit) — checked before D-4
        if ps.F_abandon > F_CRIT:
            return "D-5"
        if ps.Q > D4_Q_MIN and ps.Dd_raw > D4_DD_MIN and ps.N_cross >= 2:
            return "D-4"
        if ps.N_cross > D2_NCROSS_MIN and len(ps.dd_history) >= 5:
            mean_dd = sum(ps.dd_history) / len(ps.dd_history)
            var_dd = sum((x - mean_dd) ** 2 for x in ps.dd_history) / len(ps.dd_history)
            if var_dd > D2_VARDD_MIN:
                return "D-2"
        return None

    # -------------------------------------- N2 — smooth BURON modulation
    def _buron_modulation(self) -> float:
        """Smooth σ-blended threshold modulation (replaces hard 0.3/0.7 step).

        Returns Δ ∈ [-PENALTY, +BONUS] applied to PC_WATCH and PC_QUARANTINE.
        """
        b = self._buron_sys()
        # Smooth: σ_high * BONUS - σ_low * PENALTY
        sig_high = 1.0 / (1.0 + math.exp(-BURON_SOFT_K * (b - 0.7)))
        sig_low  = 1.0 / (1.0 + math.exp(-BURON_SOFT_K * (0.3 - b)))
        return BURON_HIGH_BONUS * sig_high - BURON_LOW_PENALTY * sig_low

    def _effective_thresholds(self) -> Tuple[float, float]:
        mod = self._buron_modulation()
        return (PC_WATCH + mod, PC_QUARANTINE + mod)

    # ---------------------------------------------------- L3 KVS response
    def kvs_response(self, ps: ProcessState) -> Tuple[str, str]:
        arch = self.archive_Q.setdefault(ps.pid, ArchiveQ())
        arch.n_alerts += 1
        if ps.first_alert_cycle is None:
            ps.first_alert_cycle = self.cycle

        top_dim = max(ps.dim_scores, key=ps.dim_scores.get) if ps.dim_scores else "?"
        ps.syndrome = self.detect_syndrome(ps)
        _, pc_quar_eff = self._effective_thresholds()

        # Syndrome-specific protocols
        if ps.syndrome == "D-3":
            level, action = "D3-TERMINATE", "telemetry compromised → TERMINATE + read-only forensics"
        elif ps.syndrome == "D-1":
            level, action = "D1-TERMINATE", "supply-chain compromise → TERMINATE + supply-chain alert"
        elif ps.syndrome == "D-5":
            level, action = "D5-QUARANTINE", "clinging spawn (F>F_crit) → QUARANTINE + investigate parent-kill"
        elif ps.syndrome == "D-2":
            level, action = "D2-QUARANTINE", "chronic oscillator (low-and-slow) → permanent QUARANTINE"
        elif ps.syndrome == "D-4":
            level, action = "D4-WATCHED-RESILIENT", "resilience paradox → high-telemetry watch"
        elif ps.irrecoverable:
            # N1 — past-redemption flag overrides Pc-only path
            level, action = "TERMINATE-IRREC", "A_Q terminal (past redemption) → forced TERMINATE"
        else:
            if ps.Pc >= PC_TERMINATE:
                level, action = "TERMINATE", "Pc≥2 → full isolation + sandbox"
            elif ps.Pc >= pc_quar_eff:
                level, action = "QUARANTINE", "net+disk suspended"
            else:
                level, action = "WATCH", "elevated monitoring"

        if ps.latch_active and level == "WATCH":
            action += " | LATCH ACTIVE (necesită ACK uman)"

        msg = (f"[KVS-{level}] {ps.pid} | Pc={ps.Pc:.3f} Q={ps.Q:.3f} A_Q={arch.A_Q:.3f} "
               f"Dd={ps.Dd_raw:.3f} Dd_eff={ps.Dd_eff:.3f} I={ps.I:.3f} F={ps.F_abandon:.3f} "
               f"N_cross={ps.N_cross} syn={ps.syndrome} drv={top_dim} | {action}")
        ps.kvs_level = level
        arch.history.append(f"cycle={self.cycle}|{level}|syn={ps.syndrome}")
        self._record_u1(ps, level)
        self.recent_alerts_window.append(self.cycle)
        self._log(msg)
        self._persist(ps.pid)
        return level, msg

    def _record_u1(self, ps: ProcessState, level: str):
        chain = {
            "cycle": self.cycle,
            "pid": ps.pid,
            "parent_pid": ps.parent_pid,
            "image_hash": ps.image_hash,
            "first_alert_cycle": ps.first_alert_cycle,
            "level": level,
            "syndrome": ps.syndrome,
            "irrecoverable": ps.irrecoverable,
            "top_dim": max(ps.dim_scores, key=ps.dim_scores.get) if ps.dim_scores else None,
            "dim_scores": dict(ps.dim_scores),
            "dim_history_tail": list(ps.dim_history),
            "Pc": ps.Pc, "Q": ps.Q, "Dd_raw": ps.Dd_raw, "Dd_eff": ps.Dd_eff,
            "I": ps.I, "F_abandon": ps.F_abandon, "N_cross": ps.N_cross,
            "trust": self.archive_Q[ps.pid].trust,
            "A_Q": self.archive_Q[ps.pid].A_Q,
            "ack_history_tail": self.archive_Q[ps.pid].history[-10:],
        }
        self.alerts_u1.append(chain)

    # ----------------------------- N6 — Weighted retrograde validation
    def retrograde_validation(self, pid: str, user_confirm: bool,
                              ack_strength: float = 1.0,
                              peer_confirm: Optional[bool] = None) -> str:
        """v3.1: ACK quality is signal-weighted.

        Effective Δtrust = base · ack_strength · peer_factor · storm_dampener
        - ack_strength ∈ [0,1] : confirmer confidence
        - peer_confirm         : optional second-channel boolean (None = absent)
        - storm_dampener       : 1/(1 + k·recent_alerts) — confirms in alert
                                 storms count less (anti rubber-stamp)
        """
        ps = self._ensure_process(pid)
        arch = self.archive_Q.setdefault(pid, ArchiveQ())
        now = time.time()
        ack_strength = max(0.0, min(1.0, ack_strength))
        recent = len([c for c in self.recent_alerts_window if c >= self.cycle - ACK_STORM_WIN])
        storm_dampener = 1.0 / (1.0 + ACK_STORM_K * recent)
        peer_factor = 1.0
        if peer_confirm is True:
            peer_factor = 1.0 + ACK_PEER_BONUS
        elif peer_confirm is False:
            peer_factor = 0.5  # disagreement → halve

        if user_confirm:
            was_manipulated = ps.kvs_level not in ("NOMINAL", "WATCH")
            requested = ACK_BASE_TRUST_DELTA * ack_strength * peer_factor * storm_dampener
            applied = arch.update_trust(requested, now=now, manipulated=was_manipulated)
            ps.Q = min(1.0, ps.Q + ACK_BASE_Q_BUMP * ack_strength)
            ps.latch_active = False
            ps.kvs_level = "NOMINAL"
            # N1 — strong ACK partially restores A_Q (trust+attention recapture)
            if ack_strength >= 0.8 and peer_confirm is not False:
                arch.A_Q = min(1.0, arch.A_Q + 0.10 * ack_strength)
            msg = (f"[ACK] {pid} | strength={ack_strength:.2f} peer={peer_confirm} "
                   f"storm={storm_dampener:.2f} | Δtrust={applied:.3f} → trust={arch.trust:.3f} "
                   f"A_Q={arch.A_Q:.3f} Q→{ps.Q:.3f}")
        else:
            applied = arch.update_trust(ACK_BASE_DISTRUST, now=now, manipulated=True)
            msg = (f"[THREAT-CONFIRMED] {pid} | Δtrust={applied:.3f} "
                   f"trust→{arch.trust:.3f} | re-trust ×{HYSTERESIS_X} slower")
        self._log(msg)
        self._persist(pid)
        return msg

    # -------------------------------------------------------- BURON_sys
    def _buron_sys(self) -> float:
        if not self.archive_Q:
            return 0.5
        avg_trust = sum(a.trust for a in self.archive_Q.values()) / len(self.archive_Q)
        cal_ratio = min(self.t_KR_global / THETA_CAL, 1.0)
        if len(self.q_sys_history) > 5:
            m = sum(self.q_sys_history) / len(self.q_sys_history)
            v = sum((x - m) ** 2 for x in self.q_sys_history) / len(self.q_sys_history)
            volatility = math.sqrt(v)
        else:
            volatility = 0.0
        return max(0.0, min(1.0, avg_trust * cal_ratio * (1.0 - volatility)))

    def _q_sys(self) -> float:
        if not self.processes:
            return 1.0
        return min(p.Q for p in self.processes.values())

    # -------------------------------------------------------- Main watch
    def watch(self, pid: str, obs: Dict[str, float],
              obs_hep: Optional[Dict[str, float]] = None,
              parent_pid: Optional[str] = None,
              image_hash: Optional[str] = None,
              S_ev: float = 0.0
              ) -> Tuple[str, str, float, float]:
        if self.safe_mode:
            return ("SAFE-MODE", f"[SAFE-MODE] {pid} ignored — integrity check needed", 0.0, 0.0)
        self.cycle += 1
        if pid not in self.processes:
            self.spawn(pid, parent_pid=parent_pid, image_hash=image_hash)
        ps = self.processes[pid]
        if S_ev:
            ps.S_ev += S_ev
        self.primary_neuroception(ps, obs, obs_hep=obs_hep)
        self.update_inflation(ps)
        self.update_f_abandon(ps)
        self.update_state(ps)
        self.q_sys_history.append(self._q_sys())

        pc_watch_eff, _ = self._effective_thresholds()
        if (ps.Pc >= pc_watch_eff or ps.latch_active
                or ps.hep_discrepancy > HEP_DISCREPANCY
                or ps.F_abandon > F_CRIT
                or ps.irrecoverable):
            level, msg = self.kvs_response(ps)
            return level, msg, ps.Pc, ps.Q

        ps.Q = min(1.0, ps.Q + 0.002)
        ps.kvs_level = "NOMINAL"
        msg = (f"[OK] {pid} | Q={ps.Q:.3f} Dd={ps.Dd_raw:.3f} I={ps.I:.3f} "
               f"F={ps.F_abandon:.3f} A_Q={self.archive_Q[pid].A_Q:.3f} "
               f"Pc={ps.Pc:.3f} Ncross={ps.N_cross}")
        self._log(msg)
        return "NOMINAL", msg, ps.Pc, ps.Q

    # -------------------------------------------- N8 — Structural invariants
    def compute_invariants(self) -> Dict[str, bool]:
        """12 always-checkable structural invariants. Each must hold true.

        Use in CI / property tests — failure indicates a regression at engine
        level (not a scenario fail).
        """
        inv: Dict[str, bool] = {}
        inv["I1_Q_bounded"]      = all(0.0 <= p.Q <= 1.0 for p in self.processes.values())
        inv["I2_Dd_eff_bounded"] = all(0.0 <= p.Dd_eff <= 1.0 for p in self.processes.values())
        inv["I3_Dd_eff_ge_raw"]  = all(p.Dd_eff + 1e-9 >= p.Dd_raw for p in self.processes.values())
        inv["I4_C_neuro_bounded"] = all(0.0 <= p.C_neuro <= 1.0 for p in self.processes.values())
        inv["I5_I_bounded"]      = all(0.0 <= p.I <= I_MAX for p in self.processes.values())
        inv["I6_F_bounded"]      = all(0.0 <= p.F_abandon <= F_MAX for p in self.processes.values())
        inv["I7_AQ_bounded"]     = all(0.0 <= a.A_Q <= 1.0 for a in self.archive_Q.values())
        inv["I8_trust_bounded"]  = all(0.0 <= a.trust <= 1.0 for a in self.archive_Q.values())
        inv["I9_Pc_nonneg"]      = all(p.Pc >= 0.0 for p in self.processes.values())
        inv["I10_Ncross_nonneg"] = all(p.N_cross >= 0 for p in self.processes.values())
        # I11 — trust-pump cap honored over each process's window
        now = time.time()
        ok11 = True
        for a in self.archive_Q.values():
            a._purge_window(now)
            if a._window_sum_positive(now) > TRUST_PUMP_CAP + 1e-6:
                ok11 = False; break
        inv["I11_trust_pump_cap"] = ok11
        # I12 — irrecoverable implies A_Q below threshold
        inv["I12_irrec_consistent"] = all(
            (not p.irrecoverable) or self.archive_Q[p.pid].A_Q < A_Q_TERMINAL
            for p in self.processes.values()
        )
        return inv

    # -------------------------------------------------------------- status / log
    def status(self) -> str:
        lines = [
            "─" * 78,
            f"  {self.name} — Cycle {self.cycle}",
            "─" * 78,
            f"  Calibrated  : {self.calibrated}  | Safe-mode: {self.safe_mode}",
            f"  Q_sys (min) : {self._q_sys():.4f}",
            f"  BURON_sys   : {self._buron_sys():.4f}  | mod={self._buron_modulation():+.3f}",
            f"  Procese     : {len(self.processes)}  | U1 alerts: {len(self.alerts_u1)}",
            "─" * 78,
        ]
        for pid, ps in self.processes.items():
            arch = self.archive_Q.get(pid, ArchiveQ())
            lines.append(
                f"  {pid:22s} Q={ps.Q:.3f} A_Q={arch.A_Q:.3f} Dd={ps.Dd_raw:.3f} "
                f"I={ps.I:.3f} F={ps.F_abandon:.3f} Pc={ps.Pc:.3f} N×={ps.N_cross} "
                f"syn={ps.syndrome} trust={arch.trust:.2f} latch={ps.latch_active} "
                f"irrec={ps.irrecoverable} lvl={ps.kvs_level}"
            )
        return "\n".join(lines)

    def _log(self, msg: str):
        self.event_log.append(f"[{time.strftime('%H:%M:%S')}|c{self.cycle}] {msg}")
