r"""[AUDIT: read-only] stix_bundle_audit — validasi OFFLINE bundle STIX
2.1 (struktur, tata bahasa ID, properti wajib, integritas referensi,
pola indikator) + ekstraksi tabel IOC datar untuk triase secai.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/implementing-security-information-sharing-with-stix2' (#0703 —
atribusi konsep; lisensi sumber Apache-2.0). Dibangun FROM SCRATCH
TANPA library stix2 (repo stdlib-first): validasi memakai stdlib
json/uuid/datetime; pola indikator di-parse MINIMALISTIK (grup [
... ], object:prop = 'nilai' / MATCHES / LIKE) — bukan parser STIX
Patterning penuh; pola yang gagal di-parse MINIMALISTIK tetap
dicatat, tidak dibuang diam-diam.

Sisi yang TIDAK diport (eksplisit): TAXII 2.1 transport/poll/push
(jaringan + API key) dan server Medallion/OpenTAXII (deployment) =
ops; konsumen feed tinggal menyimpan bundle JSON lalu mengauditnya
offline di sini (cf. intel_sync untuk freshness feed).

Kenapa secai butuh ini: bundle intel eksternal (ISAC/TIP/ATT&CK)
tidak punya jalur masuk — validasi manual = risiko "temuan terbaca
bersih karena di-skip diam-diam". Tool ini menghitung SEMUA
ketidakpatuhan (fail-closed) dan mengekstrak IOC datar yang bisa
dipakai ulang (cf. ioc_defang utk defang, campaign_correlate utk
korelasi kampanye).

Input -> mekanisme -> output:
  - Input : --bundle FILE (JSON bundle STIX 2.0/2.1) — boleh banyak.
  - Mekanisme: (1) bundle: type=='bundle', id 'bundle--<uuid>',
            objects list; (2) per objek: type dikenal (SDO/SRO/SCO/
            meta), tata bahasa id '<type>--<uuid>' + UUIDv4 utk
            SDO/SRO (SCO = UUIDv5, tak dicheck versi), properti
            umum (created; modified utk SDO/SRO/language-content),
            format timestamp RFC 3339, modified >= created,
            relationship: source_ref/target_ref resolve di bundle
            (tak resolve = lead dgn catatan bisa referensi eksternal),
            indicator: pattern_type, grammar minimalis pattern,
            valid_from/valid_until + urutan; (3) versi duplikat
            (id sama berkali-kali) -> keep modified terbaru, hitung
            stale; (4) ekstraksi IOC dari pattern yang dikenali:
            ipv4-addr/ipv6-addr/domain-name/url/email-addr/file
            (hashes + name)/windows-registry-key.
  - Output: findings.json (kontrak secai) + meta per file +
            iocs[] datar {type, value, indicator_id, name,
            hash_valid} siap dipakai tool triase lain.

Verdict: setiap ketidakpatuhan = fakta struktur terbaca dari
artefak -> status confirmed, verdict L2 REPRODUCED (bukti snippet);
validasi penuh bersih -> exit 0.

Fail-closed: file bukan bundle / tak ter-parse -> exit 2; objek
dengan type asing DIHITUNG (type-unknown, medium) — tidak pernah
dilewati; timestamp rusak dilaporkan, tidak dianggap valid.

Pemakaian:
  python tools/stix_bundle_audit.py --bundle intel.json --out f.json
Exit: 0 valid, 1 ada ketidakpatuhan, 2 error input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "secai.stix-bundle-audit/1"
MAX_FILE_BYTES = 64 * 1024 * 1024

SDO_TYPES = {
    "attack-pattern", "campaign", "course-of-action", "grouping",
    "identity", "incident", "indicator", "infrastructure",
    "intrusion-set", "malware", "malware-analysis", "note",
    "observed-data", "opinion", "report", "threat-actor", "tool",
    "vulnerability",
}
SRO_TYPES = {"relationship", "sighting"}
SCO_TYPES = {
    "artifact", "autonomous-system", "directory", "domain-name",
    "email-addr", "email-message", "file", "ipv4-addr", "ipv6-addr",
    "mac-addr", "mutex", "network-traffic", "process", "software",
    "url", "user-account", "windows-registry-key", "x509-certificate",
    "cryptographic-key", "cryptographic-hash", "archive-ext",
}
META_TYPES = {"language-content", "marking-definition",
              "extension-definition"}
KNOWN_TYPES = SDO_TYPES | SRO_TYPES | SCO_TYPES | META_TYPES

RE_STIX_ID = re.compile(r"^([a-z0-9-]+)--"
                        r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]"
                        r"{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
RE_TS = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$")

RE_HASH_HEX = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$"
                         r"|^[0-9a-fA-F]{64}$")

RE_PAT_EXTRACT = [
    # (regex, ioc_type, group no utk nilai)
    (re.compile(r"\[ ?ipv4-addr ?: ?value ?=? ?'([^']+)'"), "ipv4"),
    (re.compile(r"\[ ?ipv6-addr ?: ?value ?=? ?'([^']+)'"), "ipv6"),
    (re.compile(r"\[ ?domain-name ?: ?value ?=? ?'([^']+)'"), "domain"),
    (re.compile(r"\[ ?url ?: ?value ?=? ?'([^']+)'"), "url"),
    (re.compile(r"\[ ?email-addr ?: ?value ?=? ?'([^']+)'"), "email"),
    (re.compile(r"\[ ?file ?: ?name ?=? ?'([^']+)'"), "filename"),
    (re.compile(r"\[ ?windows-registry-key ?: ?key ?=? ?'([^']+)'"),
     "registry"),
    (re.compile(r"\[ ?file ?: ?hashes ?\. ?'?([A-Za-z0-9-]+)'? ?=?"
                r" ?'([^']+)'"), "hash"),
]
HASH_ALG = {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-512": 128,
            "sha256": 64, "sha1": 40, "md5": 32}


def parse_ts(text: str) -> datetime | None:
    if not isinstance(text, str) or not RE_TS.match(text):
        return None
    t = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def check_id(obj: dict) -> tuple[list[str], list[str]]:
    """-> (problems, uuid_hints). problems = kode ketidakpatuhan."""
    problems: list[str] = []
    otype = obj.get("type")
    oid = obj.get("id")
    m = RE_STIX_ID.match(str(oid or ""))
    if not isinstance(oid, str) or not m:
        problems.append("id-malformed")
        return problems, []
    if m.group(1) != otype:
        problems.append("id-type-mismatch")
    uid = uuid.UUID(m.group(2))
    if otype in (SDO_TYPES | SRO_TYPES | META_TYPES) and uid.version != 4:
        problems.append("id-not-uuidv4")
    return problems, [m.group(2)]


def minimal_pattern_check(pattern: str) -> bool:
    """Grammar MINIMALISTIK: dibuka/ditutup '[...]', berisi ':' dan
    salah satu operator =/MATCHES/LIKE/IN — bukan parser penuh."""
    if not isinstance(pattern, str):
        return False
    p = pattern.strip()
    if not (p.startswith("[") and p.endswith("]")):
        return False
    if ":" not in p:
        return False
    if not re.search(r"(=|!=|\bMATCHES\b|\bLIKE\b|\bIN\b)", p):
        return False
    return p.count("[") == p.count("]")


def extract_iocs(pattern: str, ind_id: str, ind_name: str) -> list[dict]:
    out: list[dict] = []
    for rx, itype, in RE_PAT_EXTRACT:
        for m in rx.finditer(pattern):
            if itype == "hash":
                alg, value = m.group(1), m.group(2)
                want = HASH_ALG.get(alg)
                valid = (want is not None and len(value) == want
                         and RE_HASH_HEX.match(value) is not None)
                out.append({"type": f"hash:{alg}", "value": value,
                            "indicator_id": ind_id,
                            "name": ind_name,
                            "hash_valid": bool(valid)})
            else:
                out.append({"type": itype, "value": m.group(1),
                            "indicator_id": ind_id,
                            "name": ind_name,
                            "hash_valid": None})
    return out


def audit_bundle(path: Path) -> tuple[list[dict], list[dict], dict]:
    """Audit satu file bundle -> (findings, iocs, meta)."""
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise SystemExit(2)
    text = raw.decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except ValueError:
        raise SystemExit(2)
    if not isinstance(data, dict) or data.get("type") != "bundle":
        raise SystemExit(2)
    findings: list[dict] = []
    iocs: list[dict] = []
    meta: dict = {"path": str(path), "objects": 0, "problems": 0,
                  "stale_versions": 0, "iocs_extracted": 0,
                  "type_counts": {}}

    bm = RE_STIX_ID.match(str(data.get("id") or ""))
    if not bm or bm.group(1) != "bundle":
        findings.append(_finding("bundle-id-malformed", "high", path,
                                 str(data.get("id")),
                                 "id bundle bukan 'bundle--<uuidv4>'"))

    objs = data.get("objects")
    if not isinstance(objs, list):
        raise SystemExit(2)
    by_id: dict[str, dict] = {}
    all_ids: set[str] = set()
    stale = 0
    for obj in objs:
        if not isinstance(obj, dict):
            findings.append(_finding("object-not-dict", "medium", path,
                                     "bukan-dict", "objek bukan mapping"))
            meta["objects"] += 1
            continue
        meta["objects"] += 1
        otype = obj.get("type")
        meta["type_counts"][str(otype)] = \
            meta["type_counts"].get(str(otype), 0) + 1
        oid = str(obj.get("id") or "")
        if otype not in KNOWN_TYPES:
            findings.append(_finding("type-unknown", "medium", path,
                                     oid, f"type '{otype}' tidak ada di "
                                          f"STIX 2.1 yang dikenal"))
            continue
        probs, _ = check_id(obj)
        for code in probs:
            findings.append(_finding(code, "medium", path, oid,
                                     f"id tidak patuh spec: {code}"))
        # properti umum
        created = parse_ts(str(obj.get("created") or ""))
        modified = parse_ts(str(obj.get("modified") or ""))
        if otype not in SCO_TYPES and created is None:
            findings.append(_finding("missing-created", "medium", path,
                                     oid, "SDO/SRO tanpa created sah"))
        needs_modified = (otype in (SDO_TYPES | SRO_TYPES)
                          or otype == "language-content")
        if needs_modified and modified is None:
            findings.append(_finding("missing-modified", "medium", path,
                                     oid, "SDO/SRO tanpa modified sah"))
        if created and modified and modified < created:
            findings.append(_finding("modified-before-created",
                                     "medium", path, oid,
                                     "modified < created"))
        # versi duplikat (hanya SDO/SRO yang ber-versi; SCO unik)
        if oid and (otype in SDO_TYPES | SRO_TYPES):
            all_ids.add(oid)
            prev = by_id.get(oid)
            if prev is None:
                by_id[oid] = obj
            else:
                stale += 1
                pm = parse_ts(str(prev.get("modified") or "")) \
                    if prev.get("modified") else None
                cm = modified or datetime.min.replace(
                    tzinfo=timezone.utc)
                if pm is not None and cm > pm:
                    by_id[oid] = obj  # versi lebih baru yang dipakai
        elif oid:
            all_ids.add(oid)

        # indicator
        if otype == "indicator":
            pattern = obj.get("pattern")
            ptype = obj.get("pattern_type")
            if not isinstance(pattern, str) or not pattern:
                findings.append(_finding("indicator-no-pattern", "high",
                                         path, oid,
                                         "indicator tanpa pattern"))
            else:
                if ptype == "stix" and not minimal_pattern_check(pattern):
                    findings.append(_finding("pattern-malformed", "high",
                                             path, oid,
                                             f"pattern gagal grammar "
                                             f"minimalis: {pattern[:80]}"))
                if ptype == "stix":
                    iocs.extend(extract_iocs(pattern, oid,
                                             str(obj.get("name") or "")))
            vf = parse_ts(str(obj.get("valid_from") or ""))
            if vf is None:
                findings.append(_finding("indicator-no-valid-from",
                                         "medium", path, oid,
                                         "indicator tanpa valid_from"))
            vu = parse_ts(str(obj.get("valid_until") or ""))
            if vu and vf and vu <= vf:
                findings.append(_finding("valid-until-before-from",
                                         "medium", path, oid,
                                         "valid_until <= valid_from"))
    # referensi relationship
    for obj in objs:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        for ref_key in ("source_ref", "target_ref"):
            ref = obj.get(ref_key)
            if not isinstance(ref, str) or not ref:
                findings.append(_finding("relationship-no-ref", "medium",
                                         path, str(obj.get("id")),
                                         f"tanpa {ref_key}"))
                continue
            if ref not in all_ids:
                findings.append(_finding(
                    "ref-dangling", "medium", path,
                    str(obj.get("id")),
                    f"{ref_key}='{ref}' tidak ada di bundle "
                    f"(bisa sah bila referensi lintas-bundle — "
                    f"lead, bukan pasti rusak)"))
    meta["stale_versions"] = stale
    meta["iocs_extracted"] = len(iocs)
    meta["problems"] = len(findings)
    return findings, iocs, meta


def _finding(code: str, severity: str, path: Path, target: str,
             desc: str) -> dict:
    return make_finding(
        tool="stix_bundle_audit",
        title=f"stix {code}",
        severity=severity,
        description=desc + " — ketidakpatuhan STIX 2.1 dihitung "
                    "eksplisit (fail-closed), tidak pernah dianggap "
                    "valid.",
        recommendation="Perbaiki objek/pembuat bundle; feed tak patuh "
                       "spec bisa membuat SIEM/TIP membaca kurang.",
        file_path=str(path),
        param=target or None,
        status="confirmed",
        evidence_kind="artifact-parse",
        poc=f"{code}: {desc[:120]}",
        confidence=0.9,
        finding_class="weakness",
        extra={"code": code},
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="validasi bundle STIX 2.1 + ekstraksi IOC (offline)")
    ap.add_argument("--bundle", required=True,
                    help="koma-pisah file bundle JSON")
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args(argv)

    paths: list[Path] = []
    for part in args.bundle.split(","):
        part = part.strip()
        if part:
            p = Path(part)
            if not p.is_file():
                print(f"[stix_bundle_audit] file tidak ada: {part}",
                      file=sys.stderr)
                return 2
            paths.append(p)

    all_findings: list[dict] = []
    all_iocs: list[dict] = []
    metas: list[dict] = []
    for p in paths:
        try:
            f, iocs, meta = audit_bundle(p)
        except SystemExit:
            print(f"[stix_bundle_audit] {p} bukan bundle STIX JSON "
                  "yang sah (fail-closed)", file=sys.stderr)
            return 2
        all_findings.extend(f)
        all_iocs.extend(iocs)
        metas.append(meta)

    meta = {
        "schema": SCHEMA,
        "bundles": metas,
        "iocs": all_iocs,
        "iocs_total": len(all_iocs),
        "note": "grammar pattern = minimalis (bukan parser STIX "
                "Patterning penuh); TAXII transport = ops (tidak "
                "diport)",
    }
    write_findings(args.out, all_findings, meta)
    if all_findings:
        print(f"[stix_bundle_audit] {len(all_findings)} ketidakpatuhan "
              f"({len(all_iocs)} IOC diekstrak) -> {args.out}")
        return 1
    print(f"[stix_bundle_audit] {len(metas)} bundle valid "
          f"({len(all_iocs)} IOC diekstrak) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
