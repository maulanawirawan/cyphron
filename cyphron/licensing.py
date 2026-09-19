"""licensing — tier gate di level ENGINE (kode, bukan UI).

Lisensi = license.json di folder kerja/target:
    {"licensee": "...", "tier": "basic|pro|business|god", "expires": "...", "sig": "..."}

Tier -> kemampuan (sesuai docs/PRICING-TIERS.md):
    basic    : probe pasif + scan dasar + laporan PDF (tanpa fix packs/verify/grey-box)
    pro      : + fix packs, verify delta, grey-box 1 akun, semua attack probes
    business : + perf engine manual, code_audit/sca white-box, multi-target
    god      : semuanya + session_probe multi-peran + chain tools

Pelanggaran akses = REFUSED dengan alasan lisensi. Tidak bisa dilewati dari UI
karena pemeriksaan terjadi di ToolRegistry.execute, bukan di tampilan."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

TIER_RANK = {"basic": 1, "pro": 2, "business": 3, "god": 4}

# engine -> tier minimum
ENGINE_TIERS = {
    # Tier 1 (basic): pasif + scan dasar
    "http_probe": "basic", "security_headers": "basic", "tls_audit": "basic",
    "email_probe": "basic", "crawler": "basic", "dir_probe": "basic",
    "sqli_probe": "basic", "xss_probe": "basic", "method_audit": "basic",
    "secret_scan": "basic",
    "header_policy": "basic", "ct_log": "basic", "wayback": "basic",
    "smtp_probe": "basic", "dkim_probe": "basic",
    "param_miner": "basic", "takeover": "basic",
    "cookie_audit": "basic", "sri_audit": "basic",
    # Tier 2 (pro): penambalan + verifikasi + grey-box + attack penuh
    "redirect_probe": "pro", "deep_probe": "pro", "auth_probe": "pro",
    "browser_engine": "pro", "template_probe": "pro",
    "sourcemap_probe": "pro", "ws_probe": "pro",
    "id_seq": "pro", "cache_dec": "pro", "oauth": "pro", "puzzle": "pro",
    "json_inj": "pro", "smuggle": "pro",
    "ct_conf": "pro", "verb_over": "pro", "api_ver": "pro",
    "gql_batch": "pro", "gql_depth": "pro", "gql_alias": "pro",
    "pagin": "pro", "sort_inj": "pro",
    "jwt_jku": "pro", "jwt_crack": "pro", "proto_c": "pro", "proto_s": "pro",
    "clobber": "pro", "css_inj": "pro",
    "sourcemap2": "pro", "mq_mgmt": "pro", "dom_xss": "pro", "clickj": "pro",
    "liveness_probe": "pro", "middleware_bypass": "pro", "next_image_proxy": "pro",
    "js_cred_sweep": "pro", "wp_probe": "pro", "debug_page": "basic",
    "xmlrpc_probe": "pro", "lockout": "pro", "wp_dataexp": "pro",
    "authz_bypass": "pro", "llm_probe": "pro", "exploitability": "business",
    # Tier 3 (business): kapasitas + white-box + SCA
    "load_probe": "business", "perf_engine": "business",
    "code_audit": "business", "sca_probe": "business",
    # Tier 4 (god): multi-peran / rantai / analitik dalam
    "session_probe": "god", "bola": "god", "priv_matrix": "god",
}


class License:
    def __init__(self, path: Path | None):
        self.tier = "basic"
        self.licensee = "unlicensed"
        self.expires = None
        self.valid = True
        self.reason = "no license file: basic tier only"
        if path and Path(path).exists():
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
                self.tier = str(data.get("tier", "basic")).lower()
                self.licensee = str(data.get("licensee", "unknown"))
                exp = data.get("expires")
                if exp:
                    self.expires = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                    if self.expires.tzinfo is None:
                        # naive timestamp → anggap UTC (naive vs aware = TypeError)
                        self.expires = self.expires.replace(tzinfo=timezone.utc)
                    if self.expires < datetime.now(timezone.utc):
                        self.valid = False
                        self.reason = f"license expired at {exp}"
                        self.tier = "basic"
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                self.valid = False
                self.reason = f"license file invalid: {exc}"

    def rank(self) -> int:
        return TIER_RANK.get(self.tier, 1)

    def allows(self, engine: str) -> tuple[bool, str]:
        # fail-closed: engine tak terdaftar butuh tier tertinggi (harus
        # diregistrasi eksplisit di ENGINE_TIERS — bukan lolos sebagai basic)
        needed = ENGINE_TIERS.get(engine, "god")
        if not self.valid:
            return False, f"license invalid: {self.reason}"
        if self.rank() >= TIER_RANK.get(needed, 1):
            return True, f"{self.tier} tier covers {engine} (needs {needed})"
        return False, (f"engine '{engine}' butuh tier {needed.upper()} — "
                       f"lisensimu {self.tier.upper()}. Upgrade untuk membuka.")


def gate_engine(engine: str, license_path: Path | None) -> tuple[bool, str, License]:
    lic = License(license_path)
    ok, reason = lic.allows(engine)
    return ok, reason, lic
