"""god_report — laporan tier GOD: gabung temuan live + pengetahuan KB.

Semua sumber pasif:
- temuan live  : findings.json hasil scan (engine existing + nuclei_bridge)
- CVE exposure : cpe.sqlite (feed NVD) lewat fingerprint->CPE (LEAD)
- exploit publik: files_exploits.csv (referensi, tidak dieksekusi)
Skema severity program = penentu akhir; skor CVSS dicatat sebagai data.
Output: satu markdown siap kirim (klien/Rektor/program).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .kb import edb_index, nvd_sqlite
from .kb import fingerprint as _fp
from .kb.paths import load_manifest, resolve_kb_dir


def load_scan_data(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def collect_technologies(data: dict, extra: list[str] | None = None) -> list[str]:
    texts: list[str] = list(extra or [])
    world = data.get("world") or {}
    for key, value in (world.get("technologies") or {}).items():
        texts.append(str(key))
        if value:
            texts.append(str(value))
    for f in (data.get("confirmed") or []) + (data.get("unconfirmed") or []):
        # banner/response temuan bisa memuat versi produk eksplisit
        for field in ("response", "poc", "description"):
            v = f.get(field)
            if v:
                texts.append(str(v)[:400])
    return texts


def _sev_rows(findings: list[dict]) -> list[str]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = sorted(findings, key=lambda f: (order.get(f.get("severity"), 9),
                                           -float(f.get("confidence") or 0)))
    lines = []
    for f in rows:
        lines.append(
            f"| {f.get('severity', '?').upper()} | {f.get('title', '')[:110]} | "
            f"{f.get('tool', '')} | {f.get('status', '')} | "
            f"{f.get('finding_class', '')} | {f.get('cwe') or '-'} |")
    return lines


def build(target: str, confirmed: list[dict], texts: list[str],
          kb_dir: Path | str | None = None, top: int = 15) -> tuple[str, dict]:
    kb = resolve_kb_dir(kb_dir)
    manifest = load_manifest(kb)
    src = manifest.get("sources", {})
    nvd_info = src.get("nvd") or {}
    edb_info = src.get("edb") or {}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    matches = [m for m in _fp.to_cpe(texts) if not m.note_only]
    versioned = [m for m in matches if m.versioned]

    # --- CVE exposure (pasif) ---
    cve_rows: list[dict] = []
    per_product: list[dict] = []
    db = kb / "cpe.sqlite"
    if db.exists():
        for m in versioned:
            rows, ambiguous = nvd_sqlite.query_cves_for_product(
                db, m.vendor, m.product, m.version)
            per_product.append({"product": m.names[0] if m.names else m.product,
                                "version": m.version, "cves": len(rows),
                                "ambiguous": ambiguous})
            for r in rows:
                r["product"] = f"{m.names[0] if m.names else m.product} {m.version}"
                r["cpe23"] = m.cpe23
            cve_rows.extend(rows)
        cve_rows.sort(key=lambda r: (-(r.get("cvss_score") or 0), r["id"]))
    shown = cve_rows[:top]

    # --- referensi exploit publik (pasif) ---
    edb_refs: list[dict] = []
    csv_path = kb / "edb" / "files_exploits.csv"
    if csv_path.exists():
        rows_edb = edb_index.load_index(csv_path)
        for m in versioned:
            if not m.names:
                continue
            v_hits, name_only = edb_index.find_exploits(rows_edb, m.names,
                                                        m.version)
            if v_hits or name_only:
                edb_refs.append({"product": m.names[0], "version": m.version,
                                 "hits": v_hits, "name_only": name_only})

    # --- template nuclei ---
    nuclei_dir = kb / "nuclei"
    n_templates = (len(list(nuclei_dir.rglob("*.yaml")))
                   if nuclei_dir.exists() else 0)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in confirmed:
        sev_counts[f.get("severity")] = sev_counts.get(f.get("severity"), 0) + 1

    md: list[str] = []
    md.append(f"# Laporan GOD-TIER — {target}")
    md.append("")
    md.append(f"> Dibuat {generated} oleh Cyphron (Knowledge Integration). "
              f"KB: NVD {nvd_info.get('summary', 'belum sinkron')} · "
              f"EDB {edb_info.get('summary', 'belum sinkron')} · "
              f"template nuclei {n_templates} berkas.")
    md.append("")
    md.append("**Ringkasan**: "
              + ", ".join(f"{k}={v}" for k, v in sev_counts.items() if v)
              + f" temuan live · {len(versioned)}/{len(matches)} produk "
              f"terpetakan ke CPE berversi · {len(cve_rows)} CVE rentang "
              f"cocok (LEAD pasif) · {len(edb_refs)} produk dengan exploit "
              "publik terdokumentasi.")
    md.append("")
    md.append("## 1. Temuan live (hasil scan aktif berizin)")
    md.append("")
    if confirmed:
        md.append("| Severity | Temuan | Tool | Status | Kelas | CWE |")
        md.append("|---|---|---|---|---|---|")
        md.extend(_sev_rows(confirmed))
    else:
        md.append("_Tidak ada temuan live pada lingkup terautorizasi._")
    md.append("")
    md.append("## 2. CVE exposure — LEAD pasif dari NVD (bukan klaim)")
    md.append("")
    if shown:
        md.append("| CVSS | CVE | Produk @ versi | CWE | Ringkasan |")
        md.append("|---|---|---|---|---|")
        for r in shown:
            score = (f"{r['cvss_score']:.1f}"
                     if isinstance(r.get("cvss_score"), (int, float)) else "n/a")
            md.append(f"| {score} | {r['id']} | {r['product']} | "
                      f"{r.get('cwe') or '-'} | "
                      f"{(r.get('description') or '')[:100]} |")
        if len(cve_rows) > top:
            md.append(f"\n_(menampilkan top {top} dari {len(cve_rows)} "
                      "berdasarkan CVSS — seluruh daftar tersedia via "
                      "cve_matcher)_")
        md.append("")
        md.append("Per produk: "
                  + "; ".join(f"{p['product']} {p['version']} → {p['cves']} "
                              f"CVE (ambigu dibuang: {p['ambiguous']})"
                              for p in per_product))
    else:
        md.append("_Tidak ada CVE rentang-versi yang cocok di KB (atau KB "
                  "belum tersinkron: `python -m cyphron kb --source all`)._")
    md.append("")
    md.append("## 3. Referensi exploit publik (Exploit-DB — TIDAK dieksekusi)")
    md.append("")
    if edb_refs:
        for e in edb_refs:
            ids = ", ".join(f"EDB-{h['id']}" for h in e["hits"]) or "-"
            titles = "; ".join(h["description"][:70] for h in e["hits"][:3])
            md.append(f"- **{e['product']} {e['version']}**: {ids} "
                      f"(+{e['name_only']} entri tanpa versi spesifik) — "
                      f"{titles}")
    else:
        md.append("_Tidak ada entri exploit publik yang menyebut produk+versi "
                  "secara eksplisit._")
    md.append("")
    md.append("## 4. Metodologi & disclaimer")
    md.append("")
    md.append("1. **Pasif**: bagian 2-3 dihitung dari knowledge base lokal "
              "(feed NVD + Exploit-DB) tanpa satu pun request ke target.")
    md.append("2. **Penolakan ambiguitas (deterministik)**: hanya versi "
              "eksplisit yang dipetakan; rentang "
              "versi ambigu dibuang, bukan ditebak; template Nuclei yang "
              "dijalankan hanya subset aman dan wajib mencocokkan ISI "
              "respons (bukan status code semata).")
    md.append("3. **LEAD vs CONFIRMED**: CVE exposure = kandidat untuk "
              "diteliti (status unconfirmed). Konfirmasi hanya lewat "
              "verifikasi ringan deterministik berizin.")
    md.append("4. **Severity**: skor CVSS adalah data prioritisasi; penentu "
              "akhir klaim mengikuti skema severity program yang berlaku.")
    md.append("5. Referensi EDB adalah katalog — Cyphron tidak pernah "
              "menjalankan exploit pihak ketiga ke target.")
    md.append("")
    stats = {"products": len(matches), "versioned": len(versioned),
             "cve_rows": len(cve_rows), "edb_products": len(edb_refs),
             "n_templates": n_templates, "sev_counts": sev_counts,
             "per_product": per_product}
    return "\n".join(md) + "\n", stats


def write_report(md: str, out_path: Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    return out_path
