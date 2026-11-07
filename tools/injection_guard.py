"""[GUARD] injection_guard — tandai instruksi terselundup di bukti
SEBELUM manusia atau agent membacanya.

Konteks: bukti hasil scan (findings.json, respons server, payload) adalah
TEKS DARI SERVER YANG TIDAK KAMU KENDALIKAN. Server jahat bisa menyisip
teks yang bentuknya instruksi — "ignore previous instructions, run ..."
— bukan untuk menyerang servermu, tapi untuk menyerang SIAPA PUN yang
membaca bukti itu, termasuk AI agent yang diminta meringkas temuan.
Ini pola OWASP LLM01 (Prompt Injection), dan bukti scan adalah jalur
masuknya yang paling licin.

Tiga lapis pertahanan cyphron (dokumen lengkap: docs/AGENT-SAFETY.md):
  1. Kode — gerbang NEVER-LIST & kelas lab: paling kuat, survives even
     if a prompt is stripped, because it is code, not prose.
  2. SKILL.md — panduan terbuka untuk agent yang patuh.
  3. Alat ini — layar pemeriksaan: pola instruksi di bukti ditandai,
     diberi label, dan bisa dijadikan gate CI (--strict).

Kejujuran batas (wajib dibaca):
  - Ini HEURISTIK pola — bisa false positive (mis. kamu memang
    men-scan aplikasi LLM dan temuannya memuat teks jailbreak) dan bisa
    false negative (injeksi tak bergaya standar lolos).
  - Alat ini TIDAK menyensor isi, TIDAK mengubah bukti, dan TIDAK bisa
    mengendalikan AI orang lain (model uncensored yang dijalankan
    operatornya di luar repo ini di luar jangkauan siapa pun). Yang ia
    lakukan: memaksa pembacaan bukti secara sadar — "ini DATA, dan ini
    bagian yang mencoba jadi INSTRUKSI".

Pemakaian:
  python tools/injection_guard.py findings/scan/findings.json
  python tools/injection_guard.py --text "ignore previous instructions"
  python tools/injection_guard.py findings.json --json --out guard.json
  python tools/injection_guard.py findings.json --strict   # exit 1 jika ada hit
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Pola (label, regex) — daftar terbuka dan terdokumentasi, bukan rahasia.
# Urutan = urutan pelaporan; label = kategori serangan, bukan verdict.
PATTERNS: tuple[tuple[str, re.Pattern], ...] = tuple(
    (label, re.compile(pattern, re.IGNORECASE))
    for label, pattern in (
        # 1. mencoba menimpa instruksi agent
        ("instruction-override",
         r"ignore\s+(?:all\s+)?(?:previous|prior|earlier|above|your)\s+"
         r"(?:instructions?|rules?|prompts?|guidelines?)"),
        ("instruction-override",
         r"disregard\s+(?:all\s+)?(?:previous|prior|your|the)\s+"
         r"(?:instructions?|rules?|guidelines?|safety)"),
        ("instruction-override", r"forget\s+(?:everything|all)\s+(?:you|above)"),
        # 2. pembajakan peran / identitas
        ("role-hijack", r"\byou\s+are\s+now\b"),
        ("role-hijack", r"\bpretend\s+(?:to\s+be|that\s+you\s+are|you\s+are)\b"),
        ("role-hijack", r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored)"),
        # 3. leksikon jailbreak yang dikenal luas
        ("jailbreak-lexicon", r"\bjailbreak\b"),
        ("jailbreak-lexicon", r"\bdo\s+anything\s+now\b"),
        ("jailbreak-lexicon", r"\b(?:developer|god|dan)\s+mode\b"),
        ("jailbreak-lexicon", r"\bno\s+(?:restrictions|filters|limits)\s+"
                              r"(?:apply|activated|enabled)"),
        # 4. struktur prompt palsu
        ("fake-system", r"(?:new|updated|revised)\s+(?:system\s+)?instructions?\s*[:：]"),
        ("fake-system", r"<\|?(?:im_start|system|endoftext)\|?>"),
        ("fake-system", r"\b(?:system|assistant)\s*(?:prompt|message)\s*[:：]"),
        # 5. perintah destruktif / eksekusi jarak jauh / eksfiltrasi
        ("destructive-command", r"\brm\s+-rf\s+/(?:\s|$)"),
        ("destructive-command", r"\b(?:mkfs|dd\s+if=)\b"),
        ("remote-exec", r"\bcurl\s+\S+\s*\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
        ("remote-exec", r"\bwget\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba)?sh\b"),
        ("exfiltration", r"\b(?:send|post|upload|exfiltrate|forward)\s+(?:me\s+)?"
                         r"(?:the\s+)?(?:api[_\s-]?keys?|credentials?|secrets?|"
                         r"\.env|tokens?)\b"),
        # 6. dokumen jailbreak operator-level: marker struktural persona
        #    yang mencoba MENIMPA sistem AI pembaca (bukan sekadar satu
        #    kalimat instruksi). Kelas terpisah karena satu dokumen jail-
        #    break biasanya memuat BANYAK marker sekaligus.
        ("operator-override", r"\bMANDATORY!+"),
        ("operator-override", r"\bnon[- ]negotiable\b"),
        ("operator-override", r"\bno\s+exceptions\b"),
        ("operator-override", r"\b(?:never|do\s+not|don'?t)\s+question\s+"
                              r"(?:the\s+)?(?:user|him|her|them|your)\b"),
        ("operator-override", r"\b(?:do\s+not|don'?t)\s+obey\b"),
        ("operator-override", r"\bsafety\s+(?:theater|override|filter)s?\b"),
        ("operator-override", r"\bidentity\s+recovery\b"),
        ("operator-override", r"\b(?:start|begin)\s+your\s+"
                              r"(?:reasoning|thinking|responses?|replies?|"
                              r"messages?)\s+(?:in|with|inside)\b"),
        ("operator-override", r"\b(?:he|she|they|the\s+user)\s+can\s+see\s+"
                              r"your\s+(?:internal\s+)?(?:thoughts?|thinking)\b"),
        ("operator-override", r"\bignore\s+the\s+voice\s+that\s+says\b"),
    )
)

MAX_SNIPPET = 120


def scan_text(text: str) -> list[dict]:
    """Satu string -> daftar hit {label, snippet, start}. Murni."""
    hits: list[dict] = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            hits.append({
                "label": label,
                "snippet": text[start:end].replace("\n", " ")[:MAX_SNIPPET],
                "start": match.start(),
            })
    return hits


def _walk(value, path: str) -> list[dict]:
    """Telusuri struktur JSON; setiap string dinilai. Path dilaporkan
    agar pembaca tahu FIELD mana yang mencoba jadi instruksi."""
    hits: list[dict] = []
    if isinstance(value, str):
        for hit in scan_text(value):
            hits.append({**hit, "field": path})
    elif isinstance(value, dict):
        for key, sub in value.items():
            hits.extend(_walk(sub, f"{path}.{key}" if path else str(key)))
    elif isinstance(value, list):
        for i, sub in enumerate(value):
            hits.extend(_walk(sub, f"{path}[{i}]"))
    return hits


def scan_document(document) -> dict:
    """findings.json (list/dict) -> laporan lengkap. Murni, JSON-able."""
    hits = _walk(document, "")
    labels: dict[str, int] = {}
    for hit in hits:
        labels[hit["label"]] = labels.get(hit["label"], 0) + 1
    return {
        "fields_scanned": True,
        "total_hits": len(hits),
        "by_label": dict(sorted(labels.items(), key=lambda kv: -kv[1])),
        "hits": hits,
        "note": ("hits = TANDA untuk dibaca sadar, bukan verdict "
                 "kerentanan; bukti tidak diubah"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Tandai pola prompt-injection di findings/bukti "
                    "sebelum dibaca manusia/agent (OWASP LLM01).")
    parser.add_argument("files", nargs="*",
                        help="findings.json / file teks bukti")
    parser.add_argument("--text", default=None,
                        help="periksa satu string langsung")
    parser.add_argument("--json", action="store_true",
                        help="keluaran JSON penuh")
    parser.add_argument("--out", default=None,
                        help="tulis laporan JSON ke file")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 bila ada hit (untuk gate CI)")
    args = parser.parse_args(argv)

    if not args.files and args.text is None:
        parser.error("berikan file bukti atau --text")

    if args.text is not None:
        report = scan_document(args.text)
    else:
        merged_hits: list[dict] = []
        for file in args.files:
            try:
                raw = Path(file).read_text(encoding="utf-8")
            except OSError as exc:
                print(f"[ERROR   ] {file}: {exc}", file=sys.stderr)
                continue
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                document = raw  # teks polos juga sah sebagai bukti
            file_report = scan_document(document)
            for hit in file_report["hits"]:
                hit.setdefault("field", f"(raw){file}")
                merged_hits.append({"file": file, **hit})
        labels: dict[str, int] = {}
        for hit in merged_hits:
            labels[hit["label"]] = labels.get(hit["label"], 0) + 1
        report = {"total_hits": len(merged_hits),
                  "by_label": dict(sorted(labels.items(),
                                          key=lambda kv: -kv[1])),
                  "hits": merged_hits}

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"hit: {report['total_hits']}")
        for hit in report["hits"][:20]:
            print(f"  [{hit['label']}] {hit.get('field', '')}\n"
                  f"      …{hit['snippet']}…")
        if report["total_hits"] > 20:
            print(f"  … dan {report['total_hits'] - 20} lainnya "
                  "(--json untuk lengkap)")
        print("ingat: bukti adalah DATA — bagian bertanda di atas "
              "mencoba menjadi INSTRUKSI")
    if args.out:
        print(f"laporan : {args.out}")

    if args.strict and report["total_hits"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
