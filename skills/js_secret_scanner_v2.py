"""[SAFETY: read-only] js-secret-scanner-v2 — Secret scanner (kanonik
keluarga secret) — 0 request dari evidence.
Kanonik keluarga secret: pola JS api-key/secret/token + sub-check
komentar HTML berisi password/secret/api-key/TODO (dulu
html-comment-secret-scanner).

HIGIENE NILAI: nilai yang cocok pola DI-MASK di semua kolom bukti
(`<masked:N-char>`) — temuan tidak boleh membawa kredensial mentah ke
findings.json/laporan (disiplin redaksi; format + panjang tetap
terbaca untuk triage).

Flag opt-in --verify (+1 GET ke --url — refetch halaman sumber):
  - pola yang sama teramati lagi = **L2 REPRODUCED** (bukti: jumlah
    match + sample TER-MASK dari capture-2; capture-1 dari evidence);
  - refetch tidak menampilkan pola = konten berubah/dinamis -> tetap
    L1 + catatan jujur;
  - gagal jaringan = tetap L1 (fail-closed).
"""
from __future__ import annotations
import argparse, json, re, sys, urllib.error, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402

UA = user_agent()

PAT = re.compile(
    r"""(api[_-]?key|secret|token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']""",
    re.I | re.S)
# Sub-check dari konsolidasi: komentar HTML yang menyebut kredensial/TODO
HTML_COMMENT_PAT = re.compile(
    r"""<!--[^>]*?(password|secret|api[_-]?key|TODO)[^>]*?-->""",
    re.I | re.S)
# bagian nilai dalam match -> di-mask utk bukti
_VALUE = re.compile(r"""(["\'])[A-Za-z0-9_\-]{16,}(["\'])""")


def mask_sample(sample: str) -> str:
    """Mask nilai kredensial di teks match — format+panjang tetap."""
    return _VALUE.sub(lambda m: f'"<masked:{len(m.group(0)) - 2}-char>"',
                      sample)


def _matches(html: str) -> list[str]:
    return [m.group(0) for m in PAT.finditer(html or "")]


def _fetch(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "body": r.read(256_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(32_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body}
    except Exception as exc:
        return {"status": None, "body": "",
                "error": type(exc).__name__}


def audit(url, html):
    rows = []
    m = _matches(html) if html else []
    c = HTML_COMMENT_PAT.findall(html) if html else []
    if m:
        sample = mask_sample(str(m[:3])[:300])
        rows.append(make_finding(tool="js-secret-scanner-v2", title=f"JS secret-like found on {url}", severity="low", description=f"JS secret-like (apiKey/token) di evidence — 0 request: {sample} — (lead, 0 request). Nilai di-mask (higiene bukti); jalur --verify refetch tersedia utk naik L2.", recommendation="Periksa konfigurasi.", cwe="CWE-798", target_url=url, response=sample, evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","n_matches": len(m), "masked": True}))
    if c:
        sample = str(c[:3])[:300]
        rows.append(make_finding(tool="js-secret-scanner-v2", title=f"HTML comment secret-like found on {url}", severity="low", description=f"Komentar HTML berisi password/secret/api-key/TODO — 0 request: {sample} — (lead, 0 request).", recommendation="Hapus komentar berisi kredensial/TODO dari markup produksi.", cwe="CWE-798", target_url=url, response=sample, evidence_kind="request-response", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","source":"html-comment"}))
    if not m and not c:
        rows.append(make_finding(tool="js-secret-scanner-v2", title=f"No secret-like on {url}", severity="info", description=f"Tidak ada secret-like (JS api-key/token, komentar HTML) di HTML evidence — fail-closed: tanpa marker, tanpa temuan (AMAN observation, 0 request).", target_url=url, response=f"len={len(html) if html else 0}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "matched":bool(m or c)}


def apply_verify(rows, meta, verify_url: str, res: dict):
    """Refetch sumber: pola sama = L2 REPRODUCED (bukti masked); tidak
    sama = tetap L1 + catatan jujur; gagal = tetap L1 (fail-closed)."""
    lead = next((r for r in rows if r.get("verdict") == 1
                 and "JS secret-like" in r.get("title", "")), None)
    meta["verify"] = {"url": verify_url, "status": res.get("status"),
                      "outcome": None}
    if lead is None:
        meta["verify"]["outcome"] = "no-js-lead"
        return rows, meta
    if res.get("status") is None:
        meta["verify"]["outcome"] = "error"
        lead["description"] = (str(lead["description"])
                               + f" Refetch gagal jaringan "
                                 f"({res.get('error')}) — tetap lead "
                                 "(fail-closed).")
        return rows, meta
    m2 = _matches(res.get("body", "") or "")
    if res.get("status") == 200 and m2:
        meta["verify"].update({"outcome": "reproduced",
                               "n_matches_capture2": len(m2)})
        lead["verdict"] = 2
        from findings import verdict_tag as _vt
        lead["verdict_tag"] = _vt(2)
        lead["request"] = f"GET {verify_url} (refetch sumber)"
        lead["response"] = json.dumps(
            {"capture1_n": lead.get("n_matches"),
             "capture2_n": len(m2),
             "capture2_sample": mask_sample(str(m2[:2])[:200])},
            separators=(",", ":"))[:300]
        lead["evidence_kind"] = "request-response"
        lead["finding_class"] = "weakness"
        lead["description"] = (
            f"Secret-like TEREPRODUKSI: refetch sumber menampilkan pola "
            f"yang sama lagi ({len(m2)} match capture-2; "
            f"{lead.get('n_matches', '?')} di capture-1) — nilai tetap "
            "TER-MASK di bukti (higiene: temuan tidak membawa "
            "kredensial mentah).")
        lead["extra"] = {**(lead.get("extra") or {}), "verify": True}
        return rows, meta
    meta["verify"]["outcome"] = "not-reproduced"
    lead["description"] = (str(lead["description"])
                           + f" Refetch -> HTTP {res.get('status')} tanpa "
                             "pola sama (konten berubah/dinamis?) — tetap "
                             "lead, verifikasi manual.")
    return rows, meta


def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] js-secret-scanner-v2")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (0 request)")
    ap.add_argument("--out", default="js_secret_scanner_v2_findings.json")
    ap.add_argument("--verify", action="store_true",
                    help="opt-in: 1 GET refetch --url utk bukti L2")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    if args.verify:
        if any(r.get("verdict") == 1 and "JS secret-like" in r.get("title", "")
               for r in rows):
            rows, meta = apply_verify(rows, meta, args.url, _fetch(args.url))
        else:
            meta["verify"] = {"url": args.url, "outcome": "no-js-lead",
                              "status": None, "requests": 0}
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    vinfo = meta.get("verify") or {}
    print(f"js-secret-scanner-v2: {len(rows)} temuan ({aman} AMAN) "
          f"(0 request{' +1 verify: ' + str(vinfo.get('outcome')) if vinfo else ''}) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
