"""[SAFETY: read-only] slsa_provenance_audit — audit OFFLINE dokumen
provenance in-toto/SLSA: struktur statement/DSSE, ikatan digest subjek
vs artefak nyata, dan kebijakan identitas builder/sumber. NOL jaringan.

Mengisi antrean port SKILL-PORT-QUEUE #0995 (mukul975/Anthropic-
Cybersecurity-Skills 'verifying-build-provenance-with-slsa-sigstore';
atribusi konsep, lisensi sumber Apache-2.0). Skill sumber = runbook
cosign/slsa-verifier (jaringan ke Rekor/Fulcio + Go CLI). Inti
deterministik yang diport di sini = VALIDASI ISI dokumen provenance
yang bisa dilakukan offline — bukan verifikasi kriptografi tanda
tangannya (itu ranah cosign/slsa-verifier live; status tanda tangan
DINYATAKAN JUJUR di output, tidak pernah diklaim terverifikasi).

Cek (deterministik, semua dari spesifikasi terpublikasi):
  1. struktur: DSSE envelope (payload b64 + payloadType + signatures)
     ATAU Statement in-toto polos (_type, subject[], predicateType,
     predicate); JSONL = satu dokumen per baris (format GitHub
     artifact attestations);
  2. predicateType keluarga SLSA provenance (slsa.dev/provenance/v0.1
     /v0.2/v1.0 atau legacy cosign 'slsaprovenance*'); lainnya = error
     (fail-closed, bukan ditebak);
  3. IKATAN SUBJEK: sha256 artefak nyata DIHITUNG SENDIRI dari file,
     wajib muncul di subject[].digest; mismatch = temuan high
     (artefak != klaim provenance — inti deteksi T1195);
  4. ekstraksi isi: v0.2 (builder.id, buildType, invocation
     .configSource, materials, metadata) / v1.0 (buildDefinition
     .externalParameters, runDetails.builder.id, resolvedDependencies)
     — externalParameters TIDAK di-dump mentah (bisa berisi input
     workflow sensitif); hanya field sumber yang dikenali diekstrak;
  5. kebijakan (--policy JSON): source_uri (normalisasi skema/.git/
     trailing slash), builder_id exact ATAU builder_id_prefix —
     matched/mismatched/unresolvable per field;
  6. level SLSA Build L1-L3 = klaim PRODUCER, bukan properti dokumen —
     status tanda tangan disajikan apa adanya (envelope tanpa
     signature = temuan medium 'no_signatures'; signature ada TIDAK
     berarti valid tanpa verifikasi live).

Fail-closed:
  - file provenance tidak ada / >32 MB / JSON-b64 rusak / _type bukan
    Statement / predicateType asing / subject tanpa digest{} -> entri
    error;
  - artefak tidak ada / >32 MB -> exit 2;
  - kebijakan JSON rusak / field tak dikenal / nilai kosong -> exit 2
    (typo-protection);
  - artefak tidak cocok SATU PUN subjek -> temuan high per dokumen;
  - --fail-on mismatch|policy|signature|any -> exit 1.

Pemakaian:
  python tools/slsa_provenance_audit.py --provenance a.intoto.jsonl \
      --artifact ./mybin --policy policy.json --out hasil.json
  python tools/slsa_provenance_audit.py --provenance b.json \
      --artifact a.tar.gz --artifact name2=b.tar.gz --fail-on any
Exit: 0 selesai; 1 temuan >= --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "cyphron.slsa-provenance-audit/1"
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_MATERIALS = 20
MAX_SUBJECTS = 64

STATEMENT_TYPES = (
    "https://in-toto.io/Statement/v0.1",
    "https://in-toto.io/Statement/v1",
    "https://in-toto.io/Statement/v1.0",
    "https://in-toto.io/Statement/v1.1",
)
SLSA_PREDICATE_MARKERS = (
    "https://slsa.dev/provenance/v0.1",
    "https://slsa.dev/provenance/v0.2",
    "https://slsa.dev/provenance/v1",
)
LEGACY_PREDICATES = ("slsaprovenance", "slsaprovenance0.2",
                     "slsaprovenance1")
DSSE_PAYLOAD_TYPES = ("https://in-toto.io/Statement/v1",
                      "https://in-toto.io/Statement/v0.1",
                      "application/vnd.in-toto+json")

POLICY_FIELDS = ("source_uri", "builder_id", "builder_id_prefix")

FAIL_ON_MAP = {
    "signature": ("medium", "high"),
    "policy": ("high",),
    "mismatch": ("high",),
    "any": ("medium", "high"),
}


def normalize_source_uri(uri: str) -> str:
    """Normalisasi source-uri: buang prefix 'git+' (pola configSource
    slsa-github-generator), skema umum, suffix '.git', ref '@refs/...',
    trailing slash — host:repo dibandingkan apa adanya setelah itu."""
    text = (uri or "").strip()
    if text.startswith("git+"):
        text = text[len("git+"):]
    for scheme in ("https://", "http://", "git://", "ssh://"):
        if text.startswith(scheme):
            text = text[len(scheme):]
            break
    if text.endswith(".git"):
        text = text[:-4]
    # configSource.uri versi v0.2 lazim menyertakan ref:
    # repo@refs/tags/v2.6.0 — buang dari '@refs/' (bukan user-info:
    # pola ssh://user@host tidak mengandung '@refs/')
    marker = text.find("@refs/")
    if marker != -1:
        text = text[:marker]
    return text.rstrip("/")


def is_slsa_predicate(ptype: object) -> bool:
    text = str(ptype or "").strip()
    if text.startswith(SLSA_PREDICATE_MARKERS):
        return True
    return text in LEGACY_PREDICATES


def extract_provenance(predicate: dict, version: str) -> dict:
    """Ekstraksi field sumber/builder/materials dari predicate v0.2 atau
    v1.0 (builder-specific di luar itu -> None dgn catatan)."""
    out: dict = {"predicate_version": version}
    if version == "v0.2":
        builder = predicate.get("builder")
        out["builder_id"] = (builder or {}).get("id") if isinstance(
            builder, dict) else None
        out["build_type"] = predicate.get("buildType")
        invocation = predicate.get("invocation") or {}
        config = invocation.get("configSource") or {}
        out["source_uri"] = config.get("uri") if isinstance(
            config, dict) else None
        metadata = predicate.get("metadata") or {}
        out["started_on"] = metadata.get("buildStartedOn")
        out["finished_on"] = metadata.get("buildFinishedOn")
        materials = predicate.get("materials") or []
        out["materials"] = [
            {"uri": m.get("uri"), "digest": m.get("digest")}
            for m in materials[:MAX_MATERIALS] if isinstance(m, dict)
        ]
        out["materials_total"] = len(materials)
    elif version == "v1.0":
        build_def = predicate.get("buildDefinition") or {}
        out["build_type"] = build_def.get("buildType")
        ext = build_def.get("externalParameters")
        ext = ext if isinstance(ext, dict) else {}
        # externalParameters TIDAK di-dump mentah (bisa berisi input
        # workflow sensitif) — hanya field sumber yang dikenali
        out["source_uri"] = next(
            (ext[k] for k in ("repository", "sourceUri", "source_uri",
                              "repo_url") if isinstance(ext.get(k), str)),
            None)
        out["source_resolved"] = "recognized-field" if out[
            "source_uri"] else "builder-specific-not-recognized"
        run = predicate.get("runDetails") or {}
        builder = run.get("builder") or {}
        out["builder_id"] = builder.get("id") if isinstance(
            builder, dict) else None
        meta = run.get("metadata") or {}
        out["started_on"] = meta.get("startedOn")
        out["finished_on"] = meta.get("finishedOn")
        deps = build_def.get("resolvedDependencies") or []
        out["materials"] = [
            {"uri": m.get("uri"), "digest": m.get("digest")}
            for m in deps[:MAX_MATERIALS] if isinstance(m, dict)
        ]
        out["materials_total"] = len(deps)
    else:  # v0.1 — skema lama, bidang tidak stabil; struktur saja
        out["builder_id"] = None
        out["build_type"] = predicate.get("buildType")
        out["source_uri"] = None
        out["source_resolved"] = "v0.1-not-extracted"
        out["materials"] = []
        out["materials_total"] = 0
    return out


def file_digests(path: Path) -> dict:
    """sha256 + sha512 file artefak, streaming (jangan dibaca utuh)."""
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha512.update(chunk)
    return {"sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}


def parse_policy(raw: object) -> dict:
    """Validasi kebijakan: field dikenal, nilai non-kosong string —
    typo = ValueError (exit 2), bukan policy diam-diam kosong."""
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not raw:
        raise ValueError("policy harus objek dengan minimal satu field "
                         f"dari {POLICY_FIELDS}")
    unknown = set(raw) - set(POLICY_FIELDS)
    if unknown:
        raise ValueError(f"field policy tak dikenal: {sorted(unknown)} "
                         f"(sah: {POLICY_FIELDS})")
    policy: dict = {}
    for field in POLICY_FIELDS:
        val = raw.get(field)
        if val is None:
            continue
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"policy.{field} harus string non-kosong")
        policy[field] = val.strip()
    if not policy:
        raise ValueError("policy tidak punya field efektif")
    return policy


def check_policy(policy: dict, source_uri: object,
                 builder_id: object) -> list:
    """Nilai kebijakan vs isi dokumen -> matched/mismatched/
    unresolvable per field (unresolvable = field kebijakan ada tapi
    dokumen tak menyediakan — fail-closed, bukan diam-diam lolos)."""
    checks: list[dict] = []
    if "source_uri" in policy:
        if not source_uri:
            checks.append({"field": "source_uri",
                           "expected": policy["source_uri"],
                           "found": None,
                           "result": "unresolvable"})
        else:
            match = (normalize_source_uri(str(source_uri)) ==
                     normalize_source_uri(policy["source_uri"]))
            checks.append({"field": "source_uri",
                           "expected": policy["source_uri"],
                           "found": str(source_uri),
                           "result": "matched" if match
                           else "mismatched"})
    if "builder_id" in policy:
        if not builder_id:
            checks.append({"field": "builder_id",
                           "expected": policy["builder_id"],
                           "found": None,
                           "result": "unresolvable"})
        else:
            checks.append({"field": "builder_id",
                           "expected": policy["builder_id"],
                           "found": str(builder_id),
                           "result": "matched" if str(builder_id) ==
                           policy["builder_id"] else "mismatched"})
    if "builder_id_prefix" in policy:
        if not builder_id:
            checks.append({"field": "builder_id_prefix", "expected":
                           policy["builder_id_prefix"], "found": None,
                           "result": "unresolvable"})
        else:
            checks.append({"field": "builder_id_prefix",
                           "expected": policy["builder_id_prefix"],
                           "found": str(builder_id),
                           "result": "matched" if str(builder_id).
                           startswith(policy["builder_id_prefix"])
                           else "mismatched"})
    return checks


def parse_documents(path: Path) -> list:
    """Baca file provenance -> list dokumen; JSONL = satu per baris.
    Envelope DSSE payload di-decode TANPA verifikasi signature.
    Galat struktur = ValueError."""
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"provenance terlalu besar (> {MAX_FILE_BYTES}"
                         " b)")
    text = raw.decode("utf-8-sig", errors="replace")
    docs: list = []
    lines = text.splitlines()
    if not any(line.strip() for line in lines):
        raise ValueError("provenance kosong")
    for idx, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"baris {idx}: JSON rusak: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"baris {idx}: bukan objek JSON")
        if "payload" in obj:
            payload_b64 = obj.get("payload")
            if not isinstance(payload_b64, str) or not payload_b64:
                raise ValueError(f"baris {idx}: envelope tanpa payload")
            try:
                payload = base64.b64decode(payload_b64, validate=True)
            except Exception as exc:
                raise ValueError(f"baris {idx}: payload base64 rusak: "
                                 f"{exc}") from exc
            try:
                statement = json.loads(payload.decode("utf-8"))
            except ValueError as exc:
                raise ValueError(f"baris {idx}: payload bukan JSON: "
                                 f"{exc}") from exc
            sigs = obj.get("signatures")
            sig_count = len(sigs) if isinstance(sigs, list) else 0
            docs.append({"line": idx, "envelope": True,
                         "payload_type": obj.get("payloadType"),
                         "signatures": sig_count,
                         "statement": statement})
        else:
            docs.append({"line": idx, "envelope": False,
                         "payload_type": None, "signatures": 0,
                         "statement": obj})
    return docs


def audit_statement(statement: object, digests: dict, policy: dict,
                    explicit_names: list) -> dict:
    """Audit SATU statement in-toto: struktur, predicate, ikatan
    subjek, ekstraksi, kebijakan, findings. ValueError = input
    salah (fail-closed per dokumen)."""
    if not isinstance(statement, dict):
        raise ValueError("statement bukan objek")
    stype = statement.get("_type") or statement.get("type")
    if stype not in STATEMENT_TYPES:
        raise ValueError(f"_type bukan Statement in-toto: {stype!r}")
    ptype = statement.get("predicateType")
    if not is_slsa_predicate(ptype):
        raise ValueError(f"predicateType bukan keluarga SLSA "
                         f"provenance: {ptype!r}")
    if str(ptype).endswith("/v1") or str(ptype).endswith("/v1.0"):
        version = "v1.0"
    elif str(ptype).endswith("/v0.2"):
        version = "v0.2"
    elif str(ptype).endswith("/v0.1"):
        version = "v0.1"
    else:  # legacy cosign ('slsaprovenance' dst.) = bentuk v0.2
        version = "v0.2"
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ValueError("predicate bukan objek")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("statement tanpa subject[]")
    if len(subjects) > MAX_SUBJECTS:
        raise ValueError(f"subject[] terlalu banyak (> {MAX_SUBJECTS})")
    for subj in subjects:
        if not isinstance(subj, dict) or not isinstance(
                subj.get("digest"), dict) or not subj["digest"]:
            raise ValueError("subject tanpa digest{}")

    findings: list[dict] = []
    matched = 0
    subject_digests = {str(s["digest"].get("sha256") or "").lower()
                       for s in subjects}
    if digests:
        for name, dig in digests.items():
            hit = dig["sha256"].lower() in subject_digests
            if hit:
                matched += 1
            else:
                findings.append({
                    "level": "high", "class": "subject_digest_mismatch",
                    "detail": f"artefak {name} (sha256 {dig['sha256']}"
                              ") tidak ada di subject[] dokumen — "
                              "artefak bukan klaim provenance ini "
                              "(T1195)",
                })
    else:
        findings.append({
            "level": "medium", "class": "no_artifact_checked",
            "detail": "tidak ada --artifact: ikatan subjek TIDAK "
                      "dinilai — audit hanya struktur + kebijakan",
        })

    extracted = extract_provenance(predicate, version)
    policy_checks = check_policy(policy, extracted.get("source_uri"),
                                 extracted.get("builder_id"))
    for chk in policy_checks:
        if chk["result"] == "mismatched":
            findings.append({
                "level": "high", "class": "policy_mismatch",
                "detail": f"kebijakan {chk['field']}: diharapkan "
                          f"{chk['expected']!r}, dokumen memuat "
                          f"{chk['found']!r}",
            })
        elif chk["result"] == "unresolvable":
            findings.append({
                "level": "medium", "class": "policy_unresolvable",
                "detail": f"kebijakan {chk['field']} tak bisa dinilai "
                          "— dokumen tidak menyediakan field itu "
                          "(skema/builder-specific)",
            })

    subject_names = sorted({str(s.get("name") or "") for s in subjects
                            if isinstance(s, dict)})
    if explicit_names:
        findings.append({
            "level": "info", "class": "subject_names",
            "detail": f"nama subject: {subject_names}",
        })
        for name in explicit_names:
            if name not in subject_names:
                findings.append({
                    "level": "low", "class": "subject_name_not_found",
                    "detail": f"nama artefak eksplisit {name!r} tidak "
                              "ada di subject[] (digest tetap cocok = "
                              "kemungkinan rename distribusi)",
                })
    return {
        "predicate_type": str(ptype),
        "subject_count": len(subjects),
        "subject_names": subject_names,
        "bindings_checked": len(digests),
        "bindings_matched": matched,
        "provenance": extracted,
        "policy_checks": policy_checks,
        "findings": findings,
    }


def evaluate_doc(doc: dict, digests: dict, policy: dict,
                 explicit_names: list) -> dict:
    """Satu dokumen -> hasil audit + status signature dinyatakan
    jujur (tidak pernah diklaim terverifikasi)."""
    result = audit_statement(doc["statement"], digests, policy,
                             explicit_names)
    if doc["envelope"]:
        sig = {"envelope": True, "signature_count": doc["signatures"],
               "payload_type": doc.get("payload_type")}
        if doc["signatures"] == 0:
            sig["status"] = ("envelope TANPA signature — provenance "
                             "tidak terautentikasi")
            result["findings"].append({
                "level": "medium", "class": "no_signatures",
                "detail": "DSSE envelope tanpa signatures[] — siapa "
                          "pun bisa menulis provenance seperti ini",
            })
        else:
            sig["status"] = ("signatures ADA tapi TIDAK diverifikasi "
                             "kriptografis di sini (offline, tanpa "
                             "Rekor/Fulcio) — keputusan authentik "
                             "butuh cosign/slsa-verifier live")
    else:
        sig = {"envelope": False, "signature_count": 0,
               "status": ("statement polos tanpa envelope — tanpa "
                          "bukti penanda tanganan; provenance seperti "
                          "ini maksimal indikasi SLSA L1 (exists, "
                          "unsigned/forgeable)")}
        result["findings"].append({
            "level": "medium", "class": "unsigned_statement",
            "detail": "statement tanpa DSSE envelope/signature — "
                      "terbuka untuk dipalsukan siapa pun",
        })
    if doc.get("payload_type") is not None and doc[
            "payload_type"] not in DSSE_PAYLOAD_TYPES:
        result["findings"].append({
            "level": "info", "class": "unusual_payload_type",
            "detail": f"payloadType tidak standar: "
                      f"{doc['payload_type']!r} (diterima, dicatat)",
        })
    result["signature"] = sig
    return result


def assess_documents(docs: list, digests: dict, policy: dict,
                     explicit_names: list) -> dict:
    """Audit semua dokumen; dokumen cacat masuk errors (fail-closed
    per dokumen, sisanya tetap dinilai)."""
    audited: list[dict] = []
    errors: list[str] = []
    for doc in docs:
        try:
            row = evaluate_doc(doc, digests, policy, explicit_names)
            row["line"] = doc["line"]
            audited.append(row)
        except ValueError as exc:
            errors.append(f"baris {doc['line']}: {exc}")
    return {"audited": audited, "errors": errors}


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="slsa_provenance_audit — audit offline dokumen "
                    "provenance in-toto/SLSA: ikatan digest subjek vs "
                    "artefak nyata + kebijakan builder/sumber (read-"
                    "only, nol jaringan; signature TIDAK diverifikasi "
                    "kriptografis — ranah cosign/slsa-verifier).")
    ap.add_argument("--provenance", required=True,
                    help="file provenance: .intoto.jsonl (DSSE per "
                         "baris) atau statement JSON polos")
    ap.add_argument("--artifact", action="append", default=[],
                    metavar="[NAME=]PATH",
                    help="file artefak nyata (sha256 dihitung "
                         "sendiri; boleh berulang; NAME= utk menegaskan "
                         "nama subject)")
    ap.add_argument("--policy",
                    help="JSON kebijakan {source_uri, builder_id, "
                         "builder_id_prefix}")
    ap.add_argument("--fail-on",
                    choices=("mismatch", "policy", "signature", "any"),
                    help="exit 1 bila ada temuan kelas itu (any = "
                         "medium+)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    try:
        policy = parse_policy(
            json.loads(Path(args.policy).read_text(encoding="utf-8"))
            if args.policy else None)
    except (OSError, ValueError) as exc:
        print(f"[slsa-prov] gagal: policy: {exc}", file=sys.stderr)
        return 2

    artifacts: dict[str, tuple[Path, dict]] = {}
    try:
        for spec in args.artifact:
            if "=" in spec:
                left, right = spec.split("=", 1)
                name = left.strip()
                if not name:
                    raise ValueError(f"--artifact {spec!r}: nama kosong")
                path = Path(right)
            else:
                name, path = Path(spec).name, Path(spec)
            if not path.exists():
                raise ValueError(f"--artifact {name}: file tidak ada: "
                                 f"{path}")
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"--artifact {name}: terlalu besar "
                                 f"(> {MAX_FILE_BYTES} b)")
            artifacts[name] = (path, file_digests(path))
        docs = parse_documents(Path(args.provenance))
    except (OSError, ValueError) as exc:
        print(f"[slsa-prov] gagal: {exc}", file=sys.stderr)
        return 2

    explicit_names = [spec.split("=", 1)[0].strip()
                      for spec in args.artifact if "=" in spec]
    digests = {name: dig for name, (_, dig) in artifacts.items()}
    result = assess_documents(docs, digests, policy, explicit_names)
    all_findings = [(doc, f) for doc in result["audited"]
                    for f in doc["findings"]]
    by_class: dict[str, int] = {}
    for _, f in all_findings:
        by_class[f["class"]] = by_class.get(f["class"], 0) + 1
    out = {
        "schema": SCHEMA,
        "provenance": args.provenance,
        "artifacts": {name: {"sha256": dig["sha256"],
                             "size_bytes": path.stat().st_size}
                      for name, (path, dig) in artifacts.items()},
        "policy": policy,
        "summary": {
            "documents": len(result["audited"]),
            "errors": len(result["errors"]),
            "findings_by_class": by_class,
            "signature_note": "signature TIDAK diverifikasi di sini "
                              "(offline) — keputusan authentik butuh "
                              "cosign/slsa-verifier live; level SLSA "
                              "L1-L3 = klaim producer, bukan properti "
                              "dokumen",
        },
        "documents": result["audited"],
        "errors": result["errors"],
        "note": "ikatan subjek dihitung dari artefak nyata; "
                "externalParameters tidak di-dump mentah; status "
                "signature dinyatakan jujur per dokumen.",
    }
    rendered = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = out["summary"]
    print(f"[slsa-prov] {s['documents']} dokumen diaudit "
          f"(artefak={len(artifacts)}, "
          f"policy={'ya' if policy else 'tidak'}); "
          f"temuan={sum(by_class.values())}; error={s['errors']}")
    for doc in result["audited"]:
        print(f"  [baris {doc['line']}] predicate="
              f"{doc['predicate_type']} binding="
              f"{doc['bindings_matched']}/{doc['bindings_checked']} "
              f"policy={len(doc['policy_checks'])} cek")
        for f in doc["findings"]:
            print(f"    [{f['level']:6}] {f['class']}: {f['detail']}")
        sig = doc.get("signature") or {}
        if sig.get("status"):
            print(f"    [signature] {sig['status']}")
    if result["errors"]:
        for e in result["errors"][:10]:
            print(f"  [error   ] {e}")
    if args.fail_on:
        wanted = FAIL_ON_MAP[args.fail_on]
        if any(f["level"] in wanted for _, f in all_findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
