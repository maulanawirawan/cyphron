"""[SAFETY: read-only] typosquat-watch — pengawas sertifikat domain seed
via Certificate Transparency (crt.sh), SATU request per run.

Eskalasi 2026-10 (keputusan operator: default desain DESIGN-RDAP-RDRS-
CTI.md — seed dari watchlist, polling mengikuti nightrun, tanpa vendor).

Scope v1 (jujur terhadap batas budget 1 request):
  - DRIFT: sertifikat baru yang mencakup nama aneh pada domain seed
    (subdomain tak pernah terlihat di run sebelumnya) -> L1 lead.
    Penerbitan sertifikat adalah fakta publik CT; fakta baru = temuan.
  - GENERATOR PERMUTASI: daftar kandidat domain kembar (homoglyph,
    omission, transposisi, digit-swap) dihasilkan deterministik dan
    disertakan di meta untuk alur pemantauan lanjutan (pemeriksaan
    sibling penuh butuh budget query sendiri — tidak di sini).
Zero-FP: hanya melaporkan NAMA yang belum pernah muncul di state; tanpa
state = baseline (bukan temuan). Tidak ada klaim phishing.

Pemakaian (via orchestrator: needs=domain):
  python skills/typosquat_watch.py --domain contoh.id --out f.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "skills"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
CRTSH = "https://crt.sh/?q={domain}&output=json"
STATE_DIR = ROOT / "findings" / "night-run" / "state" / "typosquat"
MAX_RESPONSE_BYTES = 1_048_576  # 1 MB cap (JSON crt.sh bisa besar)
MAX_NAMES = 500
MAX_PERMUTATIONS = 500

DIGIT_SWAPS = {"o": "0", "i": "1", "l": "1", "e": "3", "s": "5", "a": "4"}
VOWELS = "aeiou"


def permutations(domain: str) -> list[str]:
    """Kandidat kembar deterministik (urut, tanpa duplikat, tanpa asli)."""
    seed = domain.lower().strip()
    if "." in seed:  # pakai label kiri TLD untuk permutasi
        parts = seed.split(".")
        base, tld = parts[0], "." + ".".join(parts[1:])
    else:
        base, tld = seed, ""
    out: set[str] = set()

    # 1) omission: hapus satu karakter
    for i in range(len(base)):
        out.add(base[:i] + base[i + 1:] + tld)
    # 2) transposisi: tukar dua karakter bersebelahan
    for i in range(len(base) - 1):
        out.add(base[:i] + base[i + 1] + base[i] + base[i + 2:] + tld)
    # 3) digit-swap karakter mirip
    for i, ch in enumerate(base):
        if ch in DIGIT_SWAPS:
            out.add(base[:i] + DIGIT_SWAPS[ch] + base[i + 1:] + tld)
    # 4) penyisipan vokal di tiap posisi
    for i in range(len(base) + 1):
        for v in VOWELS:
            out.add(base[:i] + v + base[i:] + tld)
    # 5) hyphenasi sederhana di tiap batas
    for i in range(1, len(base)):
        out.add(base[:i] + "-" + base[i:] + tld)

    out.discard(seed)
    return sorted(out)[:MAX_PERMUTATIONS]


def fetch_names(domain: str, timeout: float = 45.0) -> dict:
    import urllib.request
    req = urllib.request.Request(CRTSH.format(domain=domain),
                                 headers={"User-Agent": UA,
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return {"__error__": "respons melewati cap 1MB — fail-closed"}
            entries = json.loads(raw.decode())
    except Exception as exc:  # noqa: BLE001
        return {"__error__": f"{type(exc).__name__}: {exc}"}
    names: set[str] = set()
    for e in entries:
        for n in str(e.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n:
                names.add(n)
    return {"names": sorted(names)[:MAX_NAMES]}


def load_state(domain: str) -> dict | None:
    p = STATE_DIR / f"{domain}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_state(domain: str, names: list[str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / f"{domain}.json").write_text(
        json.dumps({"names": names, "taken_at": time.time()},
                   ensure_ascii=False), encoding="utf-8")


def audit(domain: str) -> tuple[list[dict], dict]:
    res = fetch_names(domain)
    if "__error__" in res:
        return [], {"ok": False, "error": res["__error__"],
                    "domain": domain, "requests": 1,
                    "safety_class": "read-only"}
    names = res["names"]
    old = load_state(domain)
    rows: list[dict] = []
    new_names: list[str] = []
    if old:
        seen = set(old.get("names") or [])
        new_names = [n for n in names if n not in seen]
    for n in new_names[:50]:
        rows.append(make_finding(
            tool="typosquat-watch",
            title=f"Sertifikat CT baru mencakup {n} (tidak pernah terlihat)",
            severity="info",
            description=(
                "Certificate Transparency mencatat penerbitan sertifikat baru "
                "untuk nama pada domain seed yang belum pernah muncul di run "
                "sebelumnya. Fakta, bukan klaim phishing — verifikasi manual "
                "(pemilik, CA, tujuan penyebaran) sebelum ditindaklanjuti."),
            recommendation=(
                "Cocokkan dengan rencana penerbitan sertifikat yang diketahui; "
                "nama tak dikenal layak diperiksa (bisa staging, bisa abuse)."),
            target_url=f"ct:{domain}",
            request=f"crt.sh?domain={domain}",
            response=json.dumps({"new_name": n})[:300],
            evidence_kind="file-manifest",
            finding_class="posture",
            confidence=0.8, status="unconfirmed", verdict=1,
            lab_only=False,
            extra={"category": "BRAND-ABUSE-KANDIDAT", "safety_class": "read-only",
                   "requests": 1, "new_name": n}))
    save_state(domain, names)
    meta = {"ok": True, "domain": domain, "requests": 1,
            "safety_class": "read-only", "names_seen": len(names),
            "new_names": len(new_names), "baseline": old is None,
            "permutation_candidates": permutations(domain)}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows, meta = audit(args.domain)
    if not meta.get("ok"):
        print(f"GAGAL: {meta.get('error')} (fail-closed — bukan klaim "
              "bersih)", file=sys.stderr)
        return 1
    write_findings(args.out, rows, meta)
    print(f"typosquat-watch: {args.domain} — {meta['names_seen']} nama, "
          f"{meta['new_names']} baru (baseline={meta['baseline']}) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
