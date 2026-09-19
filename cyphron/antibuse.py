"""antibuse — fingerprint, signing lisensi, dan sinyal anti-penyalahgunaan.

DUA LAPIS kejujuran (jangan oversell):

1. ENFORCEMENT LOKAL (dijalankan CLI, kode-enforced):
   - device_fingerprint(): binding lisensi ke mesin — lisensi yang disalin
     ke mesin lain REFUSED.
   - license_secret() + license_sig(): HMAC-SHA256 atas payload lisensi.
     Tier di atas basic tanpa sig valid = INVALID. Secret lokal disimpan
     di .cyphron/license-secret (persisten per mesin) atau env
     CYPHRON_LICENSE_SECRET. CATATAN JUJUR: ini tamper-EVIDENT + anti-copy,
     BUKAN DRM mutlak — penerbitan bersifat lokal; kontrol penerbitan yang
     kuat ada di billing server dengan secret terpusat.

2. SINYAL SERVER-SIDE (helper murni untuk billing/edge server):
   - ja3_from_headers(): ambil JA3/JA4 fingerprint dari header CDN
     (mis. Cloudflare Cf-Ja3-Hash / x-ja3) — TLS fingerprint klien.
   - ip_abuse_signals(): sinyal IP via provider pluggable (fungsi callback,
     tidak ada panggilan jaringan di modul ini): hosting/datacenter (VPN),
     proxy, tor, negara.
   - signup_velocity(): skor laju pendaftaran per subnet-IP / device_hash /
     domain email dari daftar timestamp — bulk-account detector.
   - pow_check(): proof-of-work murah untuk signup (mahal bagi bot massal).
   - abuse_verdict(): gabungkan semua sinyal → ALLOW / CHALLENGE / DENY
     dengan skor transparan (audit-friendly).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import time
import uuid
from pathlib import Path

# ----------------------------------------------------------------- fingerprint


def device_fingerprint() -> str:
    """Hash stabil identitas mesin (SHA256). Tidak menyimpan data mentah —
    cuma digest; mesin lain pasti beda digest."""
    raw = "\x1f".join([
        platform.system(), platform.release(), platform.machine(),
        platform.node(), str(uuid.getnode()),  # MAC address
        str(os.getlogin() if hasattr(os, "getlogin") else "") or "-",
    ])
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _secret_path() -> Path:
    base = Path(os.environ.get("CYPHRON_HOME", Path.home() / ".cyphron"))
    return base / "license-secret"


def license_secret() -> bytes:
    """Secret HMAC: env CYPHRON_LICENSE_SECRET > file ~/.cyphron/license-secret
    > buat baru (persisten per mesin)."""
    env = os.environ.get("CYPHRON_LICENSE_SECRET")
    if env:
        return env.encode("utf-8")
    p = _secret_path()
    if p.exists():
        return p.read_text(encoding="utf-8").strip().encode("utf-8")
    secret = uuid.uuid4().hex + uuid.getnode().__str__()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(secret, encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return secret.encode("utf-8")


def license_sig(secret: bytes, payload: dict) -> str:
    """HMAC-SHA256 kanonik: key terurut, separator \x1e — stabil lintas run."""
    canon = "\x1e".join(f"{k}={json.dumps(payload.get(k))}"
                        for k in sorted(payload))
    return hmac.new(secret, canon.encode("utf-8"), hashlib.sha256).hexdigest()


# ------------------------------------------------------- sinyal server-side
_JA3_HEADERS = ("cf-ja3-hash", "x-ja3", "ja3", "cf-ja4", "x-ja4")


def ja3_from_headers(headers: dict) -> str | None:
    """Ambil TLS fingerprint (JA3/JA4) dari header yang diset edge/CDN.
    Return None bila tidak ada — pemanggil TIDAK boleh menganggap ini bot."""
    for h in _JA3_HEADERS:
        for k, v in (headers or {}).items():
            if k.lower() == h and v:
                return str(v)[:64]
    return None


_VPN_CACHE: dict[str, float] = {}


def ip_abuse_signals(ip: str, provider=None) -> dict:
    """Sinyal IP via provider callback (mis. layanan IP reputation).
    provider(ip) -> dict {hosting: bool, proxy: bool, tor: bool, country: str}.
    Tanpa provider: hanya heuristik lokal — jangan dipakai sendiri untuk DENY.
    """
    out = {"ip": ip, "hosting": False, "proxy": False, "tor": False,
           "country": None, "provider": bool(provider)}
    if provider:
        try:
            data = provider(ip) or {}
            out.update({k: bool(data.get(k, False))
                        for k in ("hosting", "proxy", "tor")})
            out["country"] = data.get("country")
        except Exception:
            out["provider"] = "error"
    return out


def signup_velocity(records: list[dict], window_s: int = 3600,
                    subnet_bits: int = 24) -> dict:
    """Deteksi bulk-account: hitung pendaftaran per window dalam jendela waktu
    dari akun yang paling baru. records: {ts: epoch, ip, device_hash, email}.
    Skor 0-100; > 60 = mencurigakan, > 85 = nyaris pasti bulk.
    """
    now = time.time()
    recent = [r for r in records
              if now - float(r.get("ts", 0)) <= window_s]
    subnets: dict[str, int] = {}
    devices: dict[str, int] = {}
    domains: dict[str, int] = {}
    for r in recent:
        ip = str(r.get("ip", "") or "")
        net = ".".join(ip.split(".")[:subnet_bits // 8]) if ip else "unknown"
        subnets[net] = subnets.get(net, 0) + 1
        d = str(r.get("device_hash", "") or "-")[:16]
        devices[d] = devices.get(d, 0) + 1
        mail = str(r.get("email", "") or "")
        dom = mail.rsplit("@", 1)[-1].lower() if "@" in mail else "unknown"
        domains[dom] = domains.get(dom, 0) + 1
    n = max(len(recent), 1)
    score = 0
    # satu device buka banyak akun = sinyal bulk paling kuat
    score += min(45, 45 * sum(1 for v in devices.values() if v >= 3))
    score += min(25, 25 * sum(1 for v in subnets.values() if v >= 3))
    score += (min(15, 15 * sum(1 for v in domains.values() if v >= 2))
              if len(domains) < n else 0)
    return {"signups_in_window": len(recent), "distinct_subnets": len(subnets),
            "distinct_devices": len(devices), "distinct_email_domains": len(domains),
            "score": score,
            "verdict": ("DENY" if score >= 80 else
                        "CHALLENGE" if score > 60 else "ALLOW")}


def pow_challenge(seed: str, difficulty_bits: int = 18) -> dict:
    """Server: buat tantangan PoW. Client mencari nonce; server cek hash.
    Murah untuk manusia (sekali kirim form), mahal untuk bot massal."""
    return {"seed": seed, "difficulty_bits": difficulty_bits}


def pow_solve(seed: str, difficulty_bits: int = 18) -> str:
    target = 1 << (256 - difficulty_bits)
    nonce = 0
    while True:
        h = int.from_bytes(hashlib.sha256(f"{seed}:{nonce}".encode()).digest(), "big")
        if h < target:
            return str(nonce)
        nonce += 1


def pow_check(seed: str, nonce: str, difficulty_bits: int = 18) -> bool:
    h = int.from_bytes(hashlib.sha256(f"{seed}:{nonce}".encode()).digest(), "big")
    return h < (1 << (256 - difficulty_bits))


def abuse_verdict(ja3: str | None, ip_signals: dict, velocity: dict,
                  trial_claims_same_device: bool = False) -> dict:
    """Gabungkan sinyal → ALLOW / CHALLENGE / DENY. Skor transparan:
    - VPN/datacenter TANPA sinyal buruk lain → CHALLENGE (PoW), bukan DENY
      (user sah di balik VPN jangan diblokir total).
    - device sama klaim trial lagi → DENY.
    - velocity tinggi + VPN → DENY.
    """
    score = 0
    reasons: list[str] = []
    if velocity.get("verdict") == "DENY":
        score += 45
        reasons.append("signup velocity ekstrem (bulk pattern)")
    elif velocity.get("verdict") == "CHALLENGE":
        score += 20
        reasons.append("signup velocity tinggi")
    if trial_claims_same_device:
        score += 100
        reasons.append("device fingerprint sudah pernah klaim trial")
    if ip_signals.get("hosting") or ip_signals.get("proxy"):
        score += 25
        reasons.append("IP datacenter/proxy (VPN)")
    if ip_signals.get("tor"):
        score += 30
        reasons.append("IP Tor exit")
    if velocity.get("verdict") in ("DENY", "CHALLENGE") and (
            ip_signals.get("hosting") or ip_signals.get("proxy")):
        score += 20
        reasons.append("velocity tinggi + VPN (kombinasi)")
    verdict = "DENY" if score >= 100 else "CHALLENGE" if score >= 25 else "ALLOW"
    return {"verdict": verdict, "score": score, "reasons": reasons,
            "ja3_present": bool(ja3)}
