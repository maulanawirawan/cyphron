r"""[SAFETY: read-only] ssti_engine_id — identifikasi mesin template dari
BUKTI probe SSTI (JSON/JSONL offline) utk T1190/T1059.007. TANPA
jaringan.

Input -> mekanisme -> output:
  - Input : file JSON (array) atau JSONL, satu objek per baris:
            {"payload": "<string yang dikirim>", "response": "<body>"}.
            Alias diterima: probe/payload, response/body.
  - Mekanisme: (1) deteksi EVALUASI aritmetika: hasil dihitung sendiri
            ({{7*7}} -> 49, {{8*7}} -> 56, ${7*7}, #{7*7}, <%= 7*7 %>,
            {7*7}, {{= 7*7}}) lalu dicocokkan dgn respons — respons
            yang meng-echo payload mentah ditolak (template di-escape);
            (2) pohon keputusan MESIN dari pembeda publik:
            {{7*'7'}} -> 7777777 = Jinja2 / 49 = Twig; ${.now} = 
            Freemarker; #set($a=1)$a = Velocity; {php} = Smarty;
            {{'test'.class}} = Pebble; {{config}} = Flask/Jinja2;
            (3) marker RCE: payload ber-token eksekusi (popen/exec/
            system/Runtime) DAN respons berpola output perintah
            (uid=/gid=) = bukti eksekusi nyata di bukti.
  - Output: temuan {check, severity, payload, message} + identitas mesin
            (name/confidence/discriminators) + notes pembeda yang BELUM
            ada di bukti (fail-closed: engine tanpa pembeda TIDAK
            pernah dilaporkan "aman").

Cek:
  ssti-eval-confirmed  (high)   : >= 2 payload aritmetika berbeda dievaluasi
                                  dgn hasil benar (differensial) DAN payload
                                  mentah tidak di-echo (T1190/T1059.007).
  ssti-eval-lead       (medium) : satu payload cocok saja — butuh probe
                                  pembeda kedua sebelum disebut confirmed.
  rce-marker           (high)   : respons payload eksekusi memuat pola
                                  output shell (uid=/gid=...).
  engine-identified    (info)   : mesin teridentifikasi dari pembeda
                                  (tidak memicu exit 1).

Fail-closed:
  - Bukti tidak valid / nol probe ter-parse -> exit 2.
  - Pembeda mesin yang tidak tersedia di bukti dicatat di notes sebagai
    probe yang direkomendasikan; keputusan mesin selalu dgn confidence
    eksplisit ("tentative" bila hanya satu pembeda lemah).
  - Respons yang meng-echo payload = TIDAK dihitung evaluasi (anti-FP
    escape).

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/ssti_engine_id.py --probes bukti-probe.jsonl
  python tools/ssti_engine_id.py --probes burp-intruder.json --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.ssti-engine-id/1"
MAX_FILE_BYTES = 16 * 1024 * 1024

# Payload aritmetika universal (per sintaks) -> hasil yang dihitung sendiri.
MATH_PAYLOADS: "dict[str, int]" = {
    "{{7*7}}": 49,      # Jinja2, Twig
    "{{8*7}}": 56,
    "${7*7}": 49,       # Freemarker, Velocity, Spring EL
    "#{7*7}": 49,       # Thymeleaf, Ruby ERB
    "<%= 7*7 %>": 49,   # ERB (Ruby), EJS (Node)
    "{7*7}": 49,        # Smarty
    "{{= 7*7}}": 49,    # doT.js
}

# Pembeda mesin (konsep publik PayloadsAllTheThings/SSTImap, ditulis ulang).
DISCRIMINATORS: "list[dict]" = [
    {"payload": "{{7*'7'}}", "engine": "jinja2",
     "contains": "7777777", "note": "python str*int"},
    {"payload": "{{7*'7'}}", "engine": "twig",
     "contains": "49", "note": "php loose math"},
    {"payload": "${.now}", "engine": "freemarker",
     "contains": None, "note": "tanggal/waktu ter-render"},
    {"payload": "#set($a=1)$a", "engine": "velocity",
     "contains": "1", "note": "assign+ref"},
    {"payload": "{php}1{/php}", "engine": "smarty",
     "contains": "1", "note": "tag php (Smarty <3.1)"},
    {"payload": "{{'test'.class}}", "engine": "pebble",
     "contains": None, "note": "introspeksi java"},
    {"payload": "{{config}}", "engine": "jinja2-flask",
     "contains": None, "note": "dump konfigurasi Flask"},
]

# Token eksekusi di payload + pola output shell di respons (anti-FP:
# keduanya harus ada BERSAMAAN pada probe yang sama).
EXEC_TOKENS = re.compile(
    r"popen\(|\.exec\(|system\(|Runtime\.getRuntime|ExecuteShellCommand"
    r"|Execute\(", re.I)
SHELL_OUTPUT = re.compile(r"\buid=\d+\(|\bgid=\d+\(|root:")

_RE_JSONL = re.compile(r"^\s*(\[|\{)")


def load_probes(path: Path) -> "list[dict]":
    """Baca bukti probe JSON array / JSONL -> list {payload, response}."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"bukti tidak terbaca: {exc}") from exc
    if len(raw.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError("bukti melebihi batas ukuran")
    records: list[dict] = []
    stripped = raw.strip()
    if not stripped:
        raise ValueError("bukti kosong")
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON array tidak valid: {exc}") from exc
        if not isinstance(data, list):
            raise ValueError("JSON bukan array")
        records = data
    else:
        for lineno, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"JSONL baris {lineno} tidak valid: {exc}") from exc
    probes: list[dict] = []
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            continue
        payload = rec.get("payload", rec.get("probe"))
        response = rec.get("response", rec.get("body"))
        if isinstance(payload, str) and isinstance(response, str):
            probes.append({"payload": payload, "response": response})
    if not probes:
        raise ValueError("nol probe valid (butuh field payload+response)")
    return probes


def _echoed(payload: str, response: str) -> bool:
    """Payload mentah muncul persis di respons = di-escape, bukan evaluasi."""
    return payload in response


def analyze(probes: "list[dict]") -> "dict":
    """Analisis bukti probe -> findings + engine + notes (deterministik)."""
    by_payload: "dict[str, list[str]]" = {}
    for p in probes:
        by_payload.setdefault(p["payload"], []).append(p["response"])

    findings: "list[dict]" = []
    matched_math: "list[dict]" = []
    for payload, expected in MATH_PAYLOADS.items():
        for resp in by_payload.get(payload, []):
            if _echoed(payload, resp):
                continue
            if str(expected) in resp:
                matched_math.append(
                    {"payload": payload, "expected": expected})

    evaluated = {m["payload"] for m in matched_math}
    if len(evaluated) >= 2:
        findings.append({
            "check": "ssti-eval-confirmed", "severity": "high",
            "payload": sorted(evaluated)[0],
            "message": (
                "Evaluasi template terkonfirmasi via differensial "
                f"({len(evaluated)} payload aritmetika hasilnya muncul di "
                "respons tanpa echo payload mentah) — input diproses "
                "sebagai ekspresi oleh mesin template (T1190/T1059.007)."),
        })
    elif len(evaluated) == 1:
        findings.append({
            "check": "ssti-eval-lead", "severity": "medium",
            "payload": sorted(evaluated)[0],
            "message": (
                "Satu payload aritmetika ter-evaluasi (lead) — kirim probe "
                "pembeda kedua (mis. {{8*7}} -> 56) sebelum confirmed."),
        })

    # Marker RCE: token eksekusi di payload + pola output shell di respons.
    for p in probes:
        if not EXEC_TOKENS.search(p["payload"]):
            continue
        if SHELL_OUTPUT.search(p["response"]):
            findings.append({
                "check": "rce-marker", "severity": "high",
                "payload": p["payload"],
                "message": (
                    "Respons probe eksekusi memuat pola output shell "
                    "(uid=/gid=) — bukti eksekusi perintah nyata; jangan "
                    "kirim payload destruktif, catat sebagai RCE."),
            })
            break

    # Pohon keputusan mesin.
    engine_hits: "list[str]" = []
    weak_hits: "list[str]" = []
    for disc in DISCRIMINATORS:
        for resp in by_payload.get(disc["payload"], []):
            if _echoed(disc["payload"], resp):
                continue
            if disc["contains"] is not None:
                if disc["contains"] in resp:
                    engine_hits.append(disc["engine"])
            else:
                # Pembeda tanpa literal: ada respons non-echo berbeda dari
                # math biasa = sinyal lemah (butuh konteks operator).
                weak_hits.append(disc["engine"])
    engine = None
    if engine_hits:
        winner = max(set(engine_hits), key=engine_hits.count)
        engine = {"name": winner, "confidence": "identified",
                  "discriminators": sorted(set(engine_hits))}
    elif weak_hits:
        engine = {"name": sorted(set(weak_hits))[0],
                  "confidence": "tentative",
                  "discriminators": sorted(set(weak_hits))}
    if engine is not None:
        findings.append({
            "check": "engine-identified", "severity": "info",
            "payload": "",
            "message": (
                f"Mesin template: {engine['name']} "
                f"(confidence {engine['confidence']}; pembeda: "
                f"{', '.join(engine['discriminators'])})."),
        })

    # Notes fail-closed: pembeda yang belum ada di bukti.
    seen_payloads = {p["payload"] for p in probes}
    missing = [d["payload"] for d in DISCRIMINATORS
               if d["payload"] not in seen_payloads]
    notes: "list[str]" = []
    if missing:
        notes.append(
            "pembeda belum diuji (kirim probe ini bila engine belum jelas): "
            + "; ".join(sorted(set(missing))))
    if not evaluated:
        notes.append(
            "tidak ada payload aritmetika ter-evaluasi di bukti — TIDAK "
            "dilaporkan bersih bila bukti tidak mencakup probe polyglot "
            "standar; tambahkan {{7*7}}+{{8*7}} sebelum menyimpulkan.")
    notes.append(
        "analisis offline atas bukti probe; eksekusi probe live = ranah "
        "SstiEvalPlaybook/lab berizin, bukan tool ini.")

    return {"findings": findings, "engine": engine, "notes": notes,
            "math_evaluated": sorted(evaluated)}


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Identifikasi mesin template dari bukti probe SSTI "
                    "(offline, nol jaringan).")
    ap.add_argument("--probes", required=True,
                    help="bukti probe JSON array / JSONL "
                         "(field: payload+response)")
    ap.add_argument("--fail-on", default="high",
                    choices=["medium", "high"],
                    help="severity minimum yang memicu exit 1 (default high)")
    ap.add_argument("--out", default=None,
                    help="tulis laporan JSON ke file (default stdout)")
    args = ap.parse_args(argv)

    path = Path(args.probes)
    try:
        probes = load_probes(path)
    except ValueError as exc:
        print(json.dumps({
            "schema": SCHEMA, "error": str(exc), "source": str(path),
        }, ensure_ascii=False), file=sys.stderr)
        return 2

    result = analyze(probes)
    threshold = SEVERITY_ORDER[args.fail_on]
    hit = [f for f in result["findings"]
           if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    report = {
        "schema": SCHEMA,
        "source": str(path),
        "probes_evaluated": len(probes),
        "math_evaluated": result["math_evaluated"],
        "engine": result["engine"],
        "findings": result["findings"],
        "notes": result["notes"],
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
