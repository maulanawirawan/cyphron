"""ip_intel — intel IP publik pasif via API publik gratis (tanpa kunci).

Satu permintaan per IP ke layanan intel publik (ipwho.is — HTTPS, tanpa
API key, tanpa akun) untuk geo/ASN/operator. Hasil = DATA PASIF untuk
dossier/dokumentasi (ToolResult.data), BUKAN temuan — data ini tidak
mengklaim apapun tentang "pelaku".

Guard:
  - IP divalidasi; IP privat/reserved/loopback/link-local DILEWATI dengan
    jujur ("bukan IP publik") — nol permintaan keluar;
  - satu permintaan per run per IP; timeout & graceful skip (429/error =
    "tidak tersedia", bukan datangan);
  - tanpa API key = tidak ada secret yang ditangani.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.request

from .base import Tool, ToolContext, ToolResult

_UA = {"Accept": "application/json", "User-Agent": "cyphron-ipintel/1.0"}


def ipwho_lookup(ip: str, timeout: float = 15.0) -> dict | None:
    """Lookup satu IP via ipwho.is. Return dict atau None bila gagal
    (graceful — pemanggil melaporkan 'tidak tersedia')."""
    try:
        req = urllib.request.Request(f"https://ipwho.is/{ip}", headers=_UA)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _normalize(payload: dict) -> dict:
    """Reduksi payload ke kolom pasif yang relevan (geo/ASN)."""
    conn = payload.get("connection") or {}
    flag = payload.get("flag") or {}
    return {
        "ip": payload.get("ip"),
        "type": payload.get("type"),
        "country": payload.get("country"),
        "country_code": payload.get("country_code"),
        "region": payload.get("region"),
        "city": payload.get("city"),
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
        "asn": conn.get("asn"),
        "org": conn.get("org"),
        "isp": conn.get("isp"),
        "domain": conn.get("domain"),
        "timezone": (payload.get("timezone") or {}).get("id"),
        "flag_emoji": flag.get("emoji"),
        "source": "ipwho.is (publik, tanpa kunci)",
    }


class IpIntelTool(Tool):
    name = "ip_intel"
    description = ("intel IP publik pasif (geo/ASN/operator) via API "
                   "publik tanpa kunci — data pasif, bukan temuan.")
    risk_tags = {"passive", "external"}
    source_skill = "82-recon-eksternal"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        raw = str(args.get("ip") or "").strip()
        if not raw:
            return ToolResult(tool=self.name, ok=False,
                              error="args.ip wajib")
        try:
            obj = ipaddress.ip_address(raw)
        except ValueError:
            return ToolResult(tool=self.name, ok=False,
                              error=f"IP tidak valid: {raw!r}")
        if not obj.is_global:
            return ToolResult(tool=self.name, ok=True, data={
                "ip": raw,
                "skipped": (f"{obj} bukan IP publik "
                            f"(privat/reserved/loopback) — nol permintaan"),
            })

        ctx.throttle()
        payload = ipwho_lookup(obj.compressed,
                               timeout=float(args.get("timeout", 15.0)))
        if not payload or payload.get("success") is False:
            return ToolResult(tool=self.name, ok=True, data={
                "ip": raw,
                "skipped": "layanan intel tidak tersedia saat ini "
                           "(429/error) — coba lagi nanti",
            })

        data = _normalize(payload)
        ctx.world.note(f"ip_intel: {raw} -> {data.get('country')} / "
                       f"AS{data.get('asn')} {data.get('org')}")
        data["note"] = ("data pasif pihak ketiga; geo/ASN bukan bukti "
                        "identitas pengguna (cloud/proxy/vpn umum) — "
                        "pakai untuk konteks, bukan tuduhan")
        return ToolResult(tool=self.name, ok=True, data=data)
