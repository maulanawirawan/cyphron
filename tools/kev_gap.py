"""[F69][SAFETY: read-only] kev-gap — celah coverage template komunitas
terhadap CISA KEV: CVE yang dieksploitasi-in-the-wild tapi BELUM punya
template nuclei di korpus lokal = backlog kontribusi upstream
(projectdiscovery/nuclei-templates) untuk jalur kontribusi operator.

NOL request (read-only). Sumber:
  - assets/intel/kev.json (hasil intel_sync harian)
  - assets/intel/nuclei-templates/ (korpus lokal, id template = id CVE)

Output kontrak satu pintu: baris ringkasan L0 + baris backlog prioritas
(L0 inventaris, urut dateAdded KEV terbaru, ransomware flag menaikkan
prioritas). Ini BUKAN temuan kerentanan — ini antrian kontribusi.

Pemakaian:
  python tools/kev_gap.py --out findings/kev-gap.json
  python tools/kev_gap.py --top 50
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

KEV_PATH = ROOT / "assets" / "intel" / "kev.json"
CORPUS_DIR = ROOT / "assets" / "intel" / "nuclei-templates"
ID_RE = re.compile(r"^(?:id|cve-id):\s*(CVE-\d{4}-\d{4,7})", re.M)


def load_kev(path: Path) -> tuple[list[dict], str | None]:
    if not path.is_file():
        return [], f"kev.json tidak ada: {path}"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        rows = [v for v in doc.get("vulnerabilities", []) if v.get("cveID")]
        return rows, None
    except Exception as exc:  # noqa: BLE001
        return [], f"kev.json tidak terurai: {exc}"


def corpus_ids(corpus: Path) -> set[str]:
    """Kumpulkan CVE id dari semua template yaml lokal (id: atau cve-id:)."""
    ids: set[str] = set()
    if not corpus.is_dir():
        return ids
    for y in corpus.rglob("*.yaml"):
        try:
            text = y.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        ids.update(ID_RE.findall(text))
    return ids


def gap_report(kev_rows: list[dict], corpus: Path,
               top: int = 25) -> tuple[list[dict], dict]:
    """Murni: KEV x corpus -> (rows, meta). Fail-closed: corpus hilang =
    baris audit, bukan klaim kosong."""
    rows: list[dict] = []
    ids = corpus_ids(corpus)
    if not ids:
        rows.append(make_finding(
            tool="kev-gap",
            title="Korpus nuclei-templates tidak tersedia — gap dilewati",
            severity="medium",
            description="Korpus template lokal kosong/tidak ada — "
                        "perhitungan gap tidak boleh mengklaim apa pun "
                        "(fail-closed).",
            recommendation="python tools/intel_sync.py "
                           "--components nuclei-templates",
            target_url="intel:nuclei-templates",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "KEV-GAP", "safety_class": "read-only",
                   "corpus_missing": True}))
        return rows, {"kev_entries": len(kev_rows), "backlog": 0}

    missing = [v for v in kev_rows if v["cveID"] not in ids]
    prio = sorted(
        missing,
        key=lambda v: (v.get("knownRansomwareCampaignUse") == "Known",
                       v.get("dateAdded", "")),
        reverse=True)
    backlog = prio[:max(0, top)]
    rows.append(make_finding(
        tool="kev-gap",
        title=f"Backlog kontribusi upstream: {len(missing)} CVE KEV "
              f"belum punya template komunitas",
        severity="info",
        description=f"Dari {len(kev_rows)} entri CISA KEV, {len(missing)} "
                    "belum punya template nuclei di korpus lokal — "
                    "backlog PR sah ke projectdiscovery/nuclei-templates "
                    "(jalur kontribusi operator). Prioritas: dateAdded "
                    "terbaru + ransomware flag.",
        recommendation="Tulis template deteksi (bukan eksploitasi) per "
                       "CVE, validasi `nuclei -validate`, cek PR duplikat "
                       "upstream, lalu ajukan PR.",
        target_url="https://github.com/projectdiscovery/nuclei-templates",
        evidence_kind="file-manifest", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=0,
        extra={"category": "KEV-GAP", "safety_class": "read-only",
               "kev_entries": len(kev_rows), "with_template": len(kev_rows)
               - len(missing), "backlog": len(missing),
               "prioritized": len(backlog)}))
    for v in backlog:
        rows.append(make_finding(
            tool="kev-gap",
            title=f"KEV-GAP: {v['cveID']} — {v.get('product', '?')}",
            severity="info",
            description=(f"{v.get('vendorProject', '?')} "
                         f"{v.get('product', '?')} — "
                         f"{v.get('vulnerabilityName', '')[:120]}. "
                         "Dieksploitasi-in-the-wild (CISA KEV, masuk "
                         f"{v.get('dateAdded', '?')}) namun belum ada "
                         "template komunitas."),
            recommendation="Tulis template deteksi + PR upstream "
                           "(cek dulu tidak ada PR duplikat).",
            cwe=(v.get("cwes") or [None])[0],
            target_url="https://nvd.nist.gov/vuln/detail/" + v["cveID"],
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "KEV-GAP", "safety_class": "read-only",
                   "cve": v["cveID"],
                   "vendor": v.get("vendorProject"),
                   "product": v.get("product"),
                   "date_added": v.get("dateAdded"),
                   "ransomware": v.get("knownRansomwareCampaignUse")
                   == "Known"}))
    meta = {"kev_entries": len(kev_rows),
            "with_template": len(kev_rows) - len(missing),
            "backlog": len(missing), "prioritized": len(backlog),
            "safety_class": "read-only", "requests": 0}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="findings/kev-gap.json")
    ap.add_argument("--kev", default=str(KEV_PATH))
    ap.add_argument("--corpus", default=str(CORPUS_DIR))
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()

    kev_rows, err = load_kev(Path(args.kev))
    if err:
        rows = [make_finding(
            tool="kev-gap", title=f"KEV tidak tersedia — {err}",
            severity="medium",
            description="Feed KEV lokal tidak bisa dibaca; gap tidak "
                        "boleh dihitung dari data kosong (fail-closed).",
            recommendation="python tools/intel_sync.py --components kev",
            target_url="intel:kev",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "KEV-GAP", "safety_class": "read-only",
                   "kev_missing": True})]
        write_findings(args.out, rows, {"run": "kev-gap",
                                        "safety_class": "read-only",
                                        "requests": 0,
                                        "kev_missing": True})
        print(f"kev-gap: KEV tidak tersedia -> {args.out}")
        return 0
    rows, meta = gap_report(kev_rows, Path(args.corpus), top=args.top)
    write_findings(args.out, rows, {**meta, "run": "kev-gap"})
    print(f"kev-gap: backlog={meta['backlog']} "
          f"(prioritized={meta['prioritized']}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
