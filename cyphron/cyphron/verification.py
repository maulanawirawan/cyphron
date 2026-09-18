"""verification — Truth Guard v2: protokol 3-gate formal (baseline -> attack ->
response comparison), diperkuat aturan anti-coincidence milik Cyphron. Semua
engine probe aktif wajib memakai helper ini agar temuan TRUE secara konstruksi."""

from __future__ import annotations

from dataclasses import dataclass

MIN_DELAY_MS = 2500
MIN_BODY_DIFF_BYTES = 40
MAX_SUSPECT_LEN_RATIO = 0.05


@dataclass
class ThreeGateResult:
    hit: bool
    evidence: str
    confidence: float


def gate1_baseline(baseline_body: str, marker: str) -> bool:
    """Gate 1: marker TIDAK boleh ada di baseline (anti 'angka kebetulan')."""
    return marker not in (baseline_body or "")


def gate2_attack(attack_body: str, marker: str) -> bool:
    """Gate 2: marker HARUS muncul di respons attack."""
    return marker in (attack_body or "")


def gate3_differential(baseline_status: int, baseline_body: str,
                       attack_status: int, attack_body: str,
                       min_body_diff: int = MIN_BODY_DIFF_BYTES) -> bool:
    """Gate 3: respons attack harus berbeda MATERIL dari baseline
    (status beda ATAU body beda minimal threshold) — anti no-op page."""
    if baseline_status != attack_status:
        return True
    return abs(len(baseline_body or "") - len(attack_body or "")) >= min_body_diff


def confirm_classic(baseline_body: str, baseline_status: int,
                    attack_url: str, attack_body: str, attack_status: int,
                    marker: str, min_delay_ms: int = 0) -> ThreeGateResult:
    """Protokol 3-gate lengkap untuk satu temuan kandidat."""
    if not gate1_baseline(baseline_body, marker):
        return ThreeGateResult(False, f"marker {marker!r} ada di baseline (coincidence)", 0.0)
    if not gate2_attack(attack_body, marker):
        return ThreeGateResult(False, f"marker {marker!r} tidak muncul di attack", 0.0)
    if min_delay_ms:
        # time-based: gate 3 diganti syarat delay di penelepon
        return ThreeGateResult(True, f"marker + delay >= {min_delay_ms}ms", 0.85)
    diff = gate3_differential(baseline_status, baseline_body, attack_status, attack_body)
    if not diff:
        return ThreeGateResult(False, "attack response identik dengan baseline (no-op)", 0.0)
    return ThreeGateResult(True, f"3-gate pass: marker {marker!r} unik + respons beda material", 0.9)


def confirm_timing(baseline_ms: int, attack_ms: int,
                   min_delay_ms: int = MIN_DELAY_MS) -> ThreeGateResult:
    """Untuk probe berbasis waktu (SQLi/cmdi): dua pengukuran + ambang."""
    if baseline_ms >= min_delay_ms:
        return ThreeGateResult(False, "baseline sudah lambat (jaringan lambat, bukan injeksi)", 0.0)
    if attack_ms - baseline_ms >= min_delay_ms:
        return ThreeGateResult(True, f"delay {attack_ms - baseline_ms}ms vs baseline {baseline_ms}ms", 0.85)
    return ThreeGateResult(False, f"delay hanya {attack_ms - baseline_ms}ms (< {min_delay_ms}ms)", 0.0)
