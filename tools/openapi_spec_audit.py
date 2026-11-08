r"""[SAFETY: read-only] openapi_spec_audit — audit OFFLINE keamanan dokumen
OpenAPI 3.x (JSON) untuk anti-pola skema request/response. TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0575 (mukul975/
Anthropic-Cybersecurity-Skills 'implementing-api-schema-validation-security';
atribusi konsep, lisensi sumber Apache-2.0) + cek no-auth-defined dari
checklist audit #0577 ('implementing-api-security-testing-with-42crunch').
Dibangun FROM SCRATCH: linter statis dokumen spec ditulis sendiri dari tabel
anti-pola publik sumber (additionalProperties, maxLength, pattern, enum
fixed-vocabulary, password tanpa TLS, error response tanpa schema, readOnly
di request). Skill sumber menjalankan spectral/dredd di CI + platform vendor
42Crunch; secai memilih linter JSON stdlib agar nol jaringan dan dapat
dites. Ranah TIDAK diduplikasi: api_property_scan (tangkapan respons live),
shadow_api_diff (trafik vs dokumentasi), api_docs_surface (keberadaan dokumen)
— tool ini menilai ISI spec itu sendiri, bukan kecocokannya dengan trafik.

Input -> mekanisme -> output:
  - Input : dokumen OpenAPI 3.x JSON (bukan YAML — preseden shadow_api_diff;
            YAML butuh dependensi non-stdlib).
  - Mekanisme: validasi wadah (fail-closed) -> resolve $ref internal ->
            telusuri paths -> operasi -> requestBody/responses ->
            evaluasi anti-pola per skema (request-side ketat, response-side
            dokumentasi).
  - Output: temuan {check, severity, pointer, message} + summary + notes.

Cek (semua verdict = LEAD — anti-pola spec bukan bukti eksploitasi):
  no-auth-defined       (high)  : tidak ada securitySchemes DAN tidak ada
                                  security global/operasi — API tanpa
                                  mekanisme auth yang dideklarasikan.
  op-no-security        (high)  : operasi tanpa security sendiri sementara
                                  global security kosong.
  password-no-tls       (high)  : format:password di skema request sementara
                                  ada server URL http:// non-local —
                                  kredensial lewat plaintext.
  server-url-http       (medium): server URL bukan https (localhost/
                                  127.0.0.1/::1/*.local disaring -> notes).
  req-additional-props  (medium): requestBody object dgn
                                  additionalProperties: true eksplisit —
                                  mass assignment (OWASP API6).
  req-additional-deflt  (info)  : requestBody object ber-properties tanpa
                                  additionalProperties (default JSON Schema
                                  = true) — versi lunak cek di atas.
  req-string-nomax      (medium): string request tanpa maxLength (DoS);
                                  string dengan format validasi implisit
                                  (date/date-time/uuid/email/ipv4/ipv6/
                                  binary/byte) atau enum/const disaring.
  req-read-only         (medium): properti readOnly:true mencapai
                                  requestBody — server diharapkan
                                  mengabaikannya, client bisa mengirimnya.
  req-string-nopattern  (info)  : string request tanpa pattern (injection
                                  surface; saringan sama dgn nomax).
  req-fixedvocab-noenum (info)  : properti bernama fixed-vocabulary
                                  (status/type/kind/state/category/role/
                                  currency/country/level/tier/unit) tanpa
                                  enum/const — lead heuristik, bukan pasti.
  resp-error-noschema   (info)  : respons 4xx/5xx tanpa content/schema —
                                  bentuk error tak terdokumentasi (bocor
                                  struktur internal saat panic).

Fail-closed:
  - bukan JSON / openapi bukan 3.x / paths kosong-bukan-objek -> exit 2.
  - $ref eksternal (bukan #/...) tidak diresolve -> dihitung di summary +
    notes (tidak dijadikan dasar "bersih" di cabang yang tak terlihat,
    tapi spec tetap diaudit parsial — cabang yang gagal resolve dicatat).
  - saringan localhost dinyatakan di notes, bukan diam-diam.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default info, mengikuti
yara_rule_lint/ids_rule_lint); 2 input tidak valid.

Pemakaian:
  python tools/openapi_spec_audit.py --spec openapi.json
  python tools/openapi_spec_audit.py --spec openapi.json --json hasil.json \
      --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}
MAX_DEPTH_DEFAULT = 6
# format string dgn validasi implisit -> tak wajib pattern/maxLength
IMPLICIT_FORMATS = {"date", "date-time", "time", "uuid", "email", "hostname",
                    "ipv4", "ipv6", "binary", "byte", "uri", "uri-reference"}
# nama properti yang lazimnya kosakata tertutup (heuristik fixed-vocab)
FIXED_VOCAB_TOKENS = ("status", "type", "kind", "state", "category", "role",
                      "currency", "country", "level", "tier", "unit")
LOCAL_HOST_TOKENS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", ".local",
                     "host.docker.internal")


def _is_http_local(url: str) -> bool:
    low = url.lower()
    return any(tok in low for tok in LOCAL_HOST_TOKENS)


def resolve_ref(doc: dict, ref: str) -> "dict | None":
    """Resolve $ref internal '#/a/b/c' -> sub-dokumen. Eksternal -> None."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: object = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node if isinstance(node, dict) else None


def _deref(schema: object, doc: dict, seen: set[str]) -> "tuple[dict | None, str | None]":
    """Ikat $ref (dgn pelindung siklus) -> (schema ter-iket, ref mentah)."""
    if not isinstance(schema, dict):
        return None, None
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            return None, ref  # siklus — jangan dilangi
        target = resolve_ref(doc, ref)
        if target is None:
            return None, ref  # eksternal / pointer mati
        return target, ref
    return schema, None


def _schema_pointer(section: str, path_key: str, op: str, media: str,
                    suffix: str = "") -> str:
    base = f"#/paths/{path_key}/{op}/{section}"
    if media:
        base += f"/content/{media}/schema"
    return base + (f"/{suffix}" if suffix else "")


def _audit_string_schema(sch: dict, pointer: str, findings: list[dict]) -> None:
    """Anti-pola string request: maxLength/pattern hilang (saringan format)."""
    if sch.get("type") != "string" and "maxLength" not in sch and "pattern" not in sch:
        return  # bukan kontrak string — bukan ranah cek ini
    fmt = sch.get("format")
    has_enum = "enum" in sch or "const" in sch
    implicit = isinstance(fmt, str) and fmt in IMPLICIT_FORMATS
    if implicit or has_enum:
        return
    if "maxLength" not in sch:
        findings.append({
            "check": "req-string-nomax", "severity": "medium",
            "pointer": pointer,
            "message": "string request tanpa maxLength (payload tak terbatas "
                       "-> DoS parser); tambahkan batas realistis",
        })
    if "pattern" not in sch:
        findings.append({
            "check": "req-string-nopattern", "severity": "info",
            "pointer": pointer,
            "message": "string request tanpa pattern — permukaan injeksi tak "
                       "dibatasi di kontrak",
        })


def _audit_fixed_vocab(props: dict, pointer: str,
                       findings: list[dict]) -> None:
    for name, sub in props.items():
        if not isinstance(sub, dict):
            continue
        low = name.lower()
        if not any(tok in low for tok in FIXED_VOCAB_TOKENS):
            continue
        if "enum" in sub or "const" in sub:
            continue
        findings.append({
            "check": "req-fixedvocab-noenum", "severity": "info",
            "pointer": f"{pointer}/properties/{name}",
            "message": f"properti '{name}' bernilai kosakata tertutup "
                       "(heuristik nama) tanpa enum/const — nilai tak "
                       "terduga bisa lolos validasi",
        })


def _audit_request_schema(sch: dict, doc: dict, pointer: str,
                          findings: list[dict], notes: list[str],
                          depth: int, seen: set[str]) -> None:
    """Anti-pola request-side: tambProps, maxLength/pattern, readOnly."""
    if depth > MAX_DEPTH_DEFAULT:
        notes.append(f"kedalaman maksimum dilewati di {pointer} (>= "
                     f"{MAX_DEPTH_DEFAULT})")
        return
    target, ref = _deref(sch, doc, seen)
    if target is None:
        if ref is not None:
            notes.append(f"$ref tidak terresolve: {ref} (di {pointer})")
        return
    if ref:
        seen.add(ref)

    if target.get("type") == "object":
        if target.get("additionalProperties") is True:
            findings.append({
                "check": "req-additional-props", "severity": "medium",
                "pointer": pointer,
                "message": "additionalProperties: true eksplisit pada request "
                           "body — mass assignment (OWASP API6); set false",
            })
        elif target.get("additionalProperties") is None \
                and isinstance(target.get("properties"), dict) \
                and target.get("properties"):
            if depth == 0:
                findings.append({
                    "check": "req-additional-deflt", "severity": "info",
                    "pointer": pointer,
                    "message": "request body object tanpa additionalProperties "
                               "(default JSON Schema = true) — kunci asing "
                               "diterima diam-diam",
                })
        props = target.get("properties")
        if isinstance(props, dict):
            _audit_fixed_vocab(props, pointer, findings)
            for name, sub in props.items():
                if isinstance(sub, dict) and sub.get("readOnly") is True:
                    findings.append({
                        "check": "req-read-only", "severity": "medium",
                        "pointer": f"{pointer}/properties/{name}",
                        "message": f"properti readOnly '{name}' terdeklarasi "
                                   "di request body — server diharapkan "
                                   "mengabaikan; keluarkan dari skema request",
                    })
        for name, sub in props.items() if isinstance(props, dict) else []:
            # string dicek lewat rekursi (else-branch) — jangan langsung di
            # sini juga, atau temuan teremisi ganda
            _audit_request_schema(sub, doc, f"{pointer}/properties/{name}",
                                  findings, notes, depth + 1, seen)
        items = target.get("additionalProperties")
        if isinstance(items, dict):  # map-style object
            _audit_request_schema(items, doc, f"{pointer}/additionalProperties",
                                  findings, notes, depth + 1, seen)
    elif target.get("type") == "array":
        _audit_request_schema(target.get("items"), doc,
                              f"{pointer}/items", findings, notes,
                              depth + 1, seen)
    else:
        _audit_string_schema(target, pointer, findings)
    if ref:
        seen.discard(ref)


def _has_password_format(sch: object, doc: dict, seen: set[str],
                         depth: int = 0) -> bool:
    if depth > MAX_DEPTH_DEFAULT or not isinstance(sch, dict):
        return False
    if sch.get("format") == "password":
        return True
    ref = sch.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            return False
        target = resolve_ref(doc, ref)
        if target is None:
            return False
        seen.add(ref)
        try:
            return _has_password_format(target, doc, seen, depth + 1)
        finally:
            seen.discard(ref)
    for sub in list(sch.get("properties", {}).values()) + [sch.get("items")]:
        if isinstance(sub, dict) and _has_password_format(sub, doc, seen,
                                                          depth + 1):
            return True
    return False


def _walk_operations(doc: dict) -> "list[tuple[str, str, dict]]":
    """[(path_key, method, op)] — method dari daftar operasi OpenAPI."""
    out: "list[tuple[str, str, dict]]" = []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return out
    for path_key, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() in {"get", "post", "put", "patch", "delete",
                                  "head", "options", "trace"} \
                    and isinstance(op, dict):
                out.append((path_key, method.lower(), op))
    return out


def audit_spec(doc: dict) -> "tuple[list[dict], dict, list[str]]":
    """Audit satu dokumen OpenAPI -> (findings, summary, notes). Fail-closed:
    raise ValueError bila wadah tidak valid."""
    version = doc.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise ValueError(f"openapi version tidak didukung: {version!r} "
                         "(butuh 3.x; YAML di luar cakupan stdlib — "
                         "konversi ke JSON dulu)")
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("field 'paths' kosong/bukan objek — spec tanpa "
                         "endpoint tidak bisa dinilai")

    findings: list[dict] = []
    notes: list[str] = []
    servers = doc.get("servers") if isinstance(doc.get("servers"), list) else []
    http_servers: list[str] = []
    for srv in servers:
        url = srv.get("url") if isinstance(srv, dict) else None
        if isinstance(url, str) and url.lower().startswith("http://"):
            if _is_http_local(url):
                notes.append(f"server http lokal disaring: {url}")
            else:
                http_servers.append(url)
                findings.append({
                    "check": "server-url-http", "severity": "medium",
                    "pointer": "#/servers",
                    "message": f"server URL http:// non-local: {url} — "
                               "trafik API tanpa TLS",
                })

    security_schemes = doc.get("components", {}) if isinstance(
        doc.get("components"), dict) else {}
    has_schemes = isinstance(security_schemes.get("securitySchemes"), dict) \
        and bool(security_schemes.get("securitySchemes"))
    global_security = doc.get("security")

    ops = _walk_operations(doc)
    n_req = 0
    n_resp_err = 0
    n_resp_err_noschema = 0
    for path_key, method, op in ops:
        op_security = op.get("security")
        if op_security is None and not global_security and not has_schemes:
            findings.append({
                "check": "no-auth-defined", "severity": "high",
                "pointer": f"#/paths/{path_key}/{method}",
                "message": "tidak ada securitySchemes, security global, "
                           "maupun security operasi — API tanpa auth "
                           "dideklarasikan",
            })
        elif op_security is None and not global_security:
            findings.append({
                "check": "op-no-security", "severity": "high",
                "pointer": f"#/paths/{path_key}/{method}",
                "message": "operasi tanpa security sendiri sementara "
                           "securitySchemes terdeklarasi — auth tidak "
                           "ditegakkan di operasi ini",
            })

        req_body = op.get("requestBody")
        if isinstance(req_body, dict):
            content = req_body.get("content")
            if isinstance(content, dict):
                for media, media_obj in content.items():
                    schema = media_obj.get("schema") \
                        if isinstance(media_obj, dict) else None
                    if not isinstance(schema, dict):
                        continue
                    n_req += 1
                    pointer = _schema_pointer("requestBody", path_key,
                                              method, str(media))
                    _audit_request_schema(schema, doc, pointer, findings,
                                          notes, 0, set())
                    if http_servers and _has_password_format(schema, doc,
                                                             set()):
                        findings.append({
                            "check": "password-no-tls", "severity": "high",
                            "pointer": pointer,
                            "message": "format:password di request body "
                                       "sementara server http:// non-local "
                                       "terdeklarasi — kredensial lewat "
                                       "plaintext",
                        })

        responses = op.get("responses")
        if isinstance(responses, dict):
            for code, resp in responses.items():
                code_str = str(code)
                is_error = (code_str.isdigit() and len(code_str) == 3
                            and code_str[0] in "45") \
                    or code_str in ("4XX", "5XX")
                if not is_error or not isinstance(resp, dict):
                    continue
                n_resp_err += 1
                content = resp.get("content")
                has_schema = False
                if isinstance(content, dict):
                    for media_obj in content.values():
                        if isinstance(media_obj, dict) \
                                and isinstance(media_obj.get("schema"), dict):
                            has_schema = True
                            break
                if not has_schema:
                    n_resp_err_noschema += 1
                    findings.append({
                        "check": "resp-error-noschema", "severity": "info",
                        "pointer": f"#/paths/{path_key}/{method}/responses/"
                                   f"{code_str}",
                        "message": f"respons error {code_str} tanpa schema — "
                                   "bentuk kegagalan tak terdokumentasi "
                                   "(struktur internal bisa bocor saat panic)",
                    })

    # pengaman dedup: satu temuan per (check, pointer) — SEBELUM summary,
    # agar hitungan selalu konsisten dgn daftar yang diemisikan
    deduped: list[dict] = []
    seen_keys: set[tuple[str, str]] = set()
    for f in findings:
        key = (f["check"], f["pointer"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(f)
    findings = deduped

    summary = {
        "paths": len(paths),
        "operations": len(ops),
        "request_schemas": n_req,
        "error_responses": n_resp_err,
        "error_responses_noschema": n_resp_err_noschema,
        "http_servers": len(http_servers),
        "auth_schemes": bool(has_schemes),
        "high": sum(1 for x in findings if x["severity"] == "high"),
        "medium": sum(1 for x in findings if x["severity"] == "medium"),
        "info": sum(1 for x in findings if x["severity"] == "info"),
    }
    return findings, summary, notes


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="openapi_spec_audit — audit OFFLINE anti-pola keamanan "
                    "dokumen OpenAPI 3.x JSON (fail-closed; LEAD, bukan "
                    "bukti eksploitasi).")
    ap.add_argument("--spec", required=True, help="file OpenAPI 3.x JSON")
    ap.add_argument("--json", default=None,
                    help="tulis laporan JSON ke path ini (selain stdout)")
    ap.add_argument("--fail-on", choices=sorted(SEV_ORDER), default="info",
                    help="severity minimum yang memicu exit 1 "
                         "(default info, mengikuti yara_rule_lint)")
    args = ap.parse_args(argv)

    src = Path(args.spec)
    if not src.is_file():
        print(f"error: file tidak ada: {src}", file=sys.stderr)
        return 2
    try:
        doc = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: input tidak valid: {exc}", file=sys.stderr)
        return 2
    if not isinstance(doc, dict):
        print("error: dokumen bukan objek JSON", file=sys.stderr)
        return 2
    try:
        findings, summary, notes = audit_spec(doc)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = {
        "source": str(src),
        "kind": "openapi-spec-audit",
        "attribution": "konsep #0575 mukul975/implementing-api-schema-"
                       "validation-security + #0577 42crunch checklist "
                       "(Apache-2.0) — dibangun from scratch",
        "findings": findings,
        "summary": summary,
        "notes": notes,
    }
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json:
        Path(args.json).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    threshold = SEV_ORDER[args.fail_on]
    hit = any(SEV_ORDER[f["severity"]] >= threshold for f in findings)
    if hit:
        counted = [f for f in findings
                   if SEV_ORDER[f["severity"]] >= threshold]
        print(f"-- {len(counted)} temuan >= {args.fail_on} "
              f"(high={summary['high']} medium={summary['medium']} "
              f"info={summary['info']})", file=sys.stderr)
    else:
        print("-- bersih: tidak ada temuan >= "
              f"{args.fail_on} ({len(findings)} info-level total)"
              if findings else "-- bersih", file=sys.stderr)
    for n in notes:
        print(f"note: {n}", file=sys.stderr)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
