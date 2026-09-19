"""licensing — tier gate di level ENGINE (kode, bukan UI) + lisensi bertanda tangan.

Lisensi = license.json di folder kerja/target:
    {"licensee": "...", "tier": "basic|pro|business|god", "expires": "...",
     "kind": "standard|trial", "device_hash": "sha256...", "token_limit": 150,
     "sig": "hmac-sha256 hex"}

- Sig HMAC (antibuse.license_secret + licensee+tier+expires+kind+device_hash).
  Tier di atas basic TANPA sig valid = lisensi INVALID (anti-tamper: dulu
  field `sig` hanya ada di docstring — file bisa diedit manual jadi "god").
- device_hash: binding mesin (antibuse.device_fingerprint) — lisensi yang
  disalin ke mesin lain REFUSED.
- kind=trial: token_limit kecil + report redacted (lihat pricing.py).
- Tanpa license file: basic-tier-only (perilaku lama tetap).

Tier -> kemampuan (docs/PRICING-TIERS.md):
    basic    : probe pasif + scan dasar + laporan PDF (tanpa fix packs/grey-box)
    pro      : + fix packs, verify delta, grey-box 1 akun, semua attack probes
    business : + perf engine manual, code_audit/sca white-box, multi-target
    god      : semuanya + session_probe multi-peran + chain tools
"""

from __future__ import annotations

import hmac
import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from .antibuse import license_secret, device_fingerprint, license_sig

TIER_RANK = {"basic": 1, "pro": 2, "business": 3, "god": 4}

# ---------------------------------------------------------------------------
# engine -> tier minimum. DIREGENERASI dari tool registry aktual (106 engine)
# + desain docs/PRICING-TIERS.md. Fail-closed: engine tak terdaftar butuh god.
# ---------------------------------------------------------------------------
_ENGINE_TIERS_RAW = {
    # basic: pasif + scan dasar
    "http_probe": "basic", "crawler": "basic", "dir_probe": "basic",
    "security_headers": "basic", "tls_audit": "basic", "tls_mismatch_leak": "basic",
    "method_audit": "basic", "secret_scan": "basic", "header_policy": "basic",
    "ct_log": "basic", "wayback": "basic", "smtp_probe": "basic",
    "dkim_probe": "basic", "param_miner": "basic", "cookie_audit": "basic",
    "cookie_scope": "basic", "cookie_prefix_insecure": "basic",
    "sri_missing_subresource": "basic", "csp_analyzer": "basic",
    "cors": "basic", "debug_page": "basic", "error_oracle": "basic",
    "hsts_short_maxage": "basic", "cache_control_missing": "basic",
    "referrer_policy_loose": "basic", "email_probe": "basic",
    "email_disclosure_pattern": "basic", "chain_decoder": "basic",
    "security_txt": "basic", "security_txt_quality": "basic",
    "robots_sensitive_entry": "basic", "server_banner_soft": "basic",
    "favicon_hash": "basic", "lang_detect": "basic",
    "archive_wayback_diff": "basic", "apk_pentest_kit": "basic",
    "apk_surface_probe": "basic", "browser_engine": "basic",
    "rate_header_graceful": "basic", "business_logic": "basic",
    # pro: attack probes + verifikasi aktif
    "xss_probe": "basic", "sqli_probe": "basic",
    "redirect_probe": "pro", "deep_probe": "pro", "auth_probe": "pro",
    "browser_scout": "pro", "browser_engine": "pro",
    "template_probe": "pro", "sourcemap_probe": "pro", "sourcemap2": "pro",
    "ws_probe": "pro", "cache_deception_probe": "pro", "cors_wildcard_subdomain": "pro",
    "ct_conf": "pro", "gql_introspect": "pro", "header_reflection_double": "pro",
    "js_cred_sweep": "pro", "jwt_jku": "pro", "laravel_panel": "pro",
    "liveness_probe": "pro", "load_probe": "pro", "lockout": "pro",
    "middleware_bypass": "pro", "oauth_state_bypass": "pro",
    "actuator": "pro", "admin_panel": "pro", "api_surface_probe": "pro",
    "api_version_diff": "pro", "auth_bypass_matrix": "pro",
    "bola": "pro", "cloud_bucket_probe": "basic", "session_probe": "pro",
    "subdomain_brute": "pro", "wp_probe": "pro", "wp_dataexp": "pro",
    "xmlrpc_probe": "pro", "nosqli_probe": "pro", "crlf": "pro",
    "session_cookie_probe": "pro",
    # business: verifikasi exploitability + intel + white-box
    "exploitability": "business", "cve_matcher": "business",
    "fingerprint_to_cpe": "business", "edb_reference": "business",
    "ip_intel": "business", "email_intel": "business", "github_osint": "business",
    "username_osint": "business", "passive_dns": "business",
    "nuclei_bridge": "business", "code_audit": "business", "sca_probe": "business",
    "privesc_scan": "business",
    # god: ofensif/eksploit penuh + rantai
    "jwt_exploit": "god", "rce_proof": "god", "ssti_rce": "god",
    "jndi_probe": "god", "deser_probe": "god", "ssrf_chain": "god",
    "ssrf_oob": "god", "xxe_probe": "god", "lfi_read": "god",
    "traversal": "god", "proto_pollution": "god", "host_header_poison": "god",
    "cache_poison": "god", "mass_assign": "god", "idor_mass_endpoint": "god",
    "identity_matrix": "god", "fuzz_engine": "god", "sqli_extract": "god",
    "reset_enum": "god", "register": "god",
}

# alias nama legacy (desain lama) -> nama tool aktual; dipakai saat lookup
_ENGINE_ALIASES = {
    "id_seq": "bola", "authz_bypass": "auth_bypass_matrix",
    "cache_dec": "cache_deception_probe", "oauth": "oauth_state_bypass",
    "puzzle": "business_logic", "json_inj": "error_oracle",
    "smuggle": "crlf", "api_ver": "api_version_diff", "proto_c": "crlf",
    "proto_s": "crlf", "clobber": "header_reflection_double",
    "css_inj": "xss_probe", "dom_xss": "xss_probe", "clickj": "security_headers",
    "gql_batch": "gql_introspect", "gql_depth": "gql_introspect",
    "gql_alias": "gql_introspect", "pagin": "param_miner",
    "sort_inj": "sqli_probe", "jwt_crack": "jwt_exploit",
    "mq_mgmt": "admin_panel", "next_image_proxy": "ssrf_oob",
    "priv_matrix": "identity_matrix", "perf_engine": "load_probe",
    "takeover": "cloud_bucket_probe", "liveness_probe": "liveness_probe",
}

ENGINE_TIERS = {k: v for k, v in _ENGINE_TIERS_RAW.items()}


def _norm_expiry(value) -> datetime | None:
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        # naive timestamp → anggap UTC (naive vs aware = TypeError)
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class License:
    """Lisensi bertanda tangan; sig wajib untuk tier di atas basic."""

    def __init__(self, path: Path | None):
        self.tier = "basic"
        self.licensee = "unlicensed"
        self.expires = None
        self.valid = True
        self.reason = "no license file: basic tier only"
        self.kind = "standard"
        self.device_hash = ""
        self.token_limit = None
        self.token_used = 0
        self.sig_valid = None  # None = tidak ada sig (basic-only)
        self.raw: dict = {}
        if path and Path(path).exists():
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
                self.raw = data
                self.tier = str(data.get("tier", "basic")).lower()
                self.licensee = str(data.get("licensee", "unknown"))
                self.kind = str(data.get("kind", "standard")).lower()
                self.device_hash = str(data.get("device_hash", "") or "")
                self.token_limit = data.get("token_limit")
                exp = data.get("expires")
                if exp:
                    self.expires = _norm_expiry(exp)
                    if self.expires < datetime.now(timezone.utc):
                        self.valid = False
                        self.reason = f"license expired at {exp}"
                        self.tier = "basic"
                sig = str(data.get("sig", "") or "")
                if sig:
                    expect = license_sig(
                        license_secret(), {
                            "licensee": self.licensee,
                            "tier": self.tier,
                            "expires": data.get("expires", ""),
                            "kind": self.kind,
                            "device_hash": self.device_hash,
                            "token_limit": self.token_limit,
                        })
                    self.sig_valid = hmac.compare_digest(sig, expect)
                    if not self.sig_valid and self.valid:
                        self.valid = False
                        self.reason = "license signature tidak valid"
                        self.tier = "basic"
                elif self.tier != "basic":
                    # anti-tamper: tier di atas basic wajib sig
                    self.valid = False
                    self.reason = ("license tanpa signature — tier di atas "
                                   "basic butuh sig (jalankan: cyphron license issue)")
                    self.tier = "basic"
                if self.valid and self.device_hash:
                    if self.device_hash != device_fingerprint():
                        self.valid = False
                        self.reason = ("license terikat perangkat lain "
                                       "(device_hash mismatch)")
                        self.tier = "basic"
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                self.valid = False
                self.reason = f"license file invalid: {exc}"

    def rank(self) -> int:
        return TIER_RANK.get(self.tier, 1)

    @property
    def is_trial(self) -> bool:
        return self.kind == "trial"

    def allows(self, engine: str) -> tuple[bool, str]:
        # fail-closed: engine tak terdaftar butuh tier tertinggi (harus
        # diregistrasi eksplisit di ENGINE_TIERS — bukan lolos sebagai basic)
        name = _ENGINE_ALIASES.get(engine, engine)
        needed = ENGINE_TIERS.get(name, "god")
        if not self.valid:
            return False, f"license invalid: {self.reason}"
        if self.rank() >= TIER_RANK.get(needed, 1):
            return True, f"{self.tier} tier covers {engine} (needs {needed})"
        return False, (f"engine '{engine}' butuh tier {needed.upper()} — "
                       f"lisensimu {self.tier.upper()}. Upgrade untuk membuka.")


def issue_license(path: Path, licensee: str, tier: str = "basic",
                  kind: str = "standard", days: int = 30,
                  token_limit: int | None = None,
                  bind_device: bool = True) -> dict:
    """Generate + sign license.json (lokal). Untuk produk: penerbitan penuh
    dilakukan billing server dengan secret yang sama formatnya."""
    expires = (datetime.now(timezone.utc).replace(microsecond=0)
               + timedelta(days=days)).isoformat()
    payload = {
        "licensee": licensee,
        "tier": tier if tier in TIER_RANK else "basic",
        "expires": expires,
        "kind": kind if kind in ("standard", "trial") else "standard",
        "device_hash": device_fingerprint() if bind_device else "",
        "token_limit": token_limit,
    }
    payload["sig"] = license_sig(license_secret(), payload)
    path = Path(path)
    path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    return payload


def gate_engine(engine: str, license_path: Path | None) -> tuple[bool, str, License]:
    lic = License(license_path)
    ok, reason = lic.allows(engine)
    return ok, reason, lic
