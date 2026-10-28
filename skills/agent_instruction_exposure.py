"""[SAFETY: bounded-requests] agent-instruction-exposure — file instruksi
agen AI ter-expose di webroot (F66e; latar tren Oktober 2026: hijack
agen coding via AGENTS.md/CLAUDE.md — laporan BleepingComputer
2026-10-25; file instruksi internal yang publik = peta prompt/tool +
pintu prompt injection untuk agen yang membaca repo).

Bounded MAKS 5 GET: /AGENTS.md, /CLAUDE.md, /.cursorrules, /.mcp.json,
/.windsurfrules. Signature ketat + anti-fallback SPA:
  - tolak body HTML (<!doctype/<html) walau status 200;
  - AGENTS.md: heading '# AGENTS' / 'agent instructions' / 'AGENTS.md';
  - CLAUDE.md: token 'claude' + (heading markdown ATAU 'instruction');
  - .mcp.json: JSON valid dengan key 'mcpServers' = L2 (peta server MCP);
  - .cursorrules/.windsurfrules: token konfigurasi eksplisit = L1 lead
    (bisa jadi file aturan biasa — bukan klaim sensitif otomatis).
AGENTS/CLAUDE/MCP = L2 (CWE-538). Tanpa marker = AMAN; semua probe
gagal jaringan = tanpa klaim AMAN.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 5
TIMEOUT_S = 10.0
PROBES = ("/AGENTS.md", "/CLAUDE.md", "/.cursorrules", "/.mcp.json",
          "/.windsurfrules")
_RE_AGENTS = re.compile(r"(?im)^#\s*agents?\b|agent instructions|"
                        r"\bagents\.md\b")
_RE_CLAUDE = re.compile(r"(?im)^#\s*claude\b|\bclaude\.md\b|"
                        r"\bclaude\b[^\n]{0,80}instruction")
_RE_CURSOR = re.compile(r"(?i)\bcursor\b|\brules?\b")
_RE_WINDSURF = re.compile(r"(?i)\bwindsurf\b|\brules?\b")


def _get(base: str, path: str):
    try:
        req = urllib.request.Request(
            base + path, method="GET",
            headers={"User-Agent": "cyphron-agent-config"})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return (r.status, r.read(64_000).decode("utf-8", "replace"),
                    dict(r.headers.items()))
    except urllib.error.HTTPError as e:
        return (e.code,
                (e.read(16_000) or b"").decode("utf-8", "replace"),
                dict(e.headers.items()) if e.headers else {})
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"[:120], {}


def _text_ok(body: str) -> bool:
    """Anti-fallback SPA: halaman HTML 200 bukan file konfigurasi."""
    low = body.lstrip().lower()
    if low.startswith(("<!doctype", "<html")):
        return False
    return len(body.strip()) >= 12


def _mcp_json(body: str) -> bool:
    try:
        doc = json.loads(body)
    except Exception:  # noqa: BLE001
        return False
    return isinstance(doc, dict) and "mcpServers" in doc


def _classify(path: str, body: str) -> tuple[bool, bool, str]:
    """(cocok, kuat/L2, marker) — signature per path."""
    if not _text_ok(body):
        return False, False, ""
    if path == "/AGENTS.md":
        m = _RE_AGENTS.search(body)
        return bool(m), bool(m), "AGENTS.md"
    if path == "/CLAUDE.md":
        m = _RE_CLAUDE.search(body)
        return bool(m), bool(m), "CLAUDE.md"
    if path == "/.mcp.json":
        ok = _mcp_json(body)
        return ok, ok, "mcpServers"
    if path == "/.cursorrules":
        m = _RE_CURSOR.search(body)
        return bool(m), False, ".cursorrules"
    if path == "/.windsurfrules":
        m = _RE_WINDSURF.search(body)
        return bool(m), False, ".windsurfrules"
    return False, False, ""


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): maks 5 GET -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base

    rows: list[dict] = []
    exposed: list[str] = []
    responded = 0
    for path in PROBES:
        st, body, _ = _get(base, path)
        if st is None:
            continue
        responded += 1
        if st != 200:
            continue
        hit, strong, marker = _classify(path, body)
        if not hit:
            continue
        exposed.append(path)
        rows.append(make_finding(
            tool="agent-instruction-exposure",
            title=(f"File instruksi agen ter-expose: {path}"
                   if strong else
                   f"File aturan agen kandidat ter-expose: {path}"),
            severity="medium" if strong else "low",
            description=(
                f"GET {path} -> 200 dengan signature '{marker}' "
                "(bukan fallback HTML). File instruksi agen yang publik "
                "membocorkan prompt/tool/perilaku agen dan menjadi "
                "pintu prompt injection/hijack bila repo dibaca agen "
                "coding — CWE-538."
                if strong else
                f"GET {path} -> 200 dengan token aturan ('{marker}') — "
                "lead (bisa file aturan biasa); verifikasi isi manual."),
            recommendation=("Pindahkan file instruksi ke luar webroot, "
                            "blokir akses publik (deny rule), atau "
                            "simpan di repo privat; audit prompt untuk "
                            "secret/instruksi sensitif."
                            if strong else
                            "Pastikan file aturan agen tidak perlu "
                            "publik; blokir bila tidak."),
            cwe="CWE-538", target_url=base + path,
            request=f"GET {path} -> 200",
            response=body[:150],
            evidence_kind="request-response",
            finding_class="posture" if strong else "weakness",
            confidence=1.0, status="confirmed",
            verdict=2 if strong else 1,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests", "file": path,
                   "strong": strong}))

    if not exposed:
        if responded == 0:
            rows.append(make_finding(
                tool="agent-instruction-exposure",
                title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
                severity="info",
                description=f"{MAX_GETS} GET ke {', '.join(PROBES)} "
                            "semua gagal jaringan; kegagalan koneksi "
                            "BUKAN bukti tidak-ada-file (fail-closed).",
                target_url=base,
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=0,
                extra={"category": "AMAN", "safety_class":
                       "bounded-requests", "network_error": True}))
        else:
            rows.append(make_finding(
                tool="agent-instruction-exposure",
                title=f"Tidak ada file yang dicari pada {base} "
                      f"({responded}/{MAX_GETS} respons)",
                severity="info",
                description="Tidak ada file konfigurasi agen yang "
                            "terbaca dengan signature sah (fallback "
                            "HTML ditolak) — AMAN/inventaris.",
                target_url=base,
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=0,
                extra={"category": "AMAN", "safety_class":
                       "bounded-requests"}))

    meta = {"url": base, "requests": responded, "exposed": exposed}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="agent_instruction_exposure.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"agent-instruction-exposure: exposed={meta['exposed']} "
          f"({meta['requests']} respons) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
