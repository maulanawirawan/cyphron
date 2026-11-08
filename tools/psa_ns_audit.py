r"""[AUDIT: read-only] psa_ns_audit — audit OFFLINE label Pod Security
Admission (PSA) pada manifest Namespace + AdmissionConfiguration
(PodSecurityConfiguration): linter statis yang menjawab "namespace mana
yang TIDAK sedang dienforce / salah konfigurasi" sebelum apply / dari
repo GitOps.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/implementing-pod-security-admission-controller' (#0683 — label
enforce/audit/warn, versi pinned, cluster default AdmissionConfiguration,
exemptions; atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM
SCRATCH TANPA kode sumber itu: aturan cek ditulis dari semantik publik
PSA (kubernetes.io/docs/concepts/security/pod-security-admission).
Skill sumber = runbook kubectl/cluster (label namespace, dry-run
server, baca events); tool ini memilih sisi statis: TIDAK menjalankan
kubectl dan TIDAK menyentuh cluster. Ranah tool tetangga ditulis
eksplisit: spec pod vs profil PSS (Restricted/Baseline) = k8s_podsec_audit
(B22 — B22 mencatat label PSA namespace sebagai "pemeriksaan cluster",
padahal sisi manifest GitOps-nya statis: gap inilah yang diisi tool ini);
RBAC manifest = k8s_rbac_audit; NetworkPolicy = netpol_audit (B23);
log API server saat JALAN = k8s_audit_triage.

Input -> mekanisme -> output:
  - Input   : --source FILE/DIR (YAML subset atau JSON, pola loader
              k8s_rbac_audit.parse_documents) + --min-enforce (level
              minimum utk namespace non-sistem) + --system-namespaces
              (tambahan nama namespace sistem) + --fail-on.
  - Mekanisme: ekstrak kind Namespace dan kind AdmissionConfiguration
              (objek tunggal / List.items / array), baca label prefix
              pod-security.kubernetes.io/* dan plugin PodSecurity,
              cek deterministik.
  - Output  : temuan {check, severity, object, field, message} +
              summary + notes.

Cek per Namespace:
  psa-no-labels          (high)   : namespace non-sistem TANPA label
                                     PSA apa pun — PSA tidak menyentuh
  psa-not-enforced       (medium) : hanya audit/warn (tanpa enforce) —
                                     rollout berhenti di tahap kering
  psa-enforce-privileged (high)   : enforce=privileged di namespace
                                     non-sistem
  psa-enforce-below-     (medium) : enforce lebih lemah dari
  minimum                           --min-enforce (non-sistem)
  psa-value-invalid      (high/   : nilai label bukan privileged/
                         medium)  baseline/restricted (enforce=high —
                                     admission error; audit/warn=medium)
  psa-label-unknown-     (medium) : label prefix PSA dgn suffix tidak
  suffix                            dikenal (typo = diam-diam inert)
  psa-version-unpinned   (low)    : enforce tanpa enforce-version
                                     (melayang ikut upgrade cluster)
  psa-version-invalid    (medium) : enforce-version bukan vN.N/latest
  psa-mode-inconsistent  (low)    : audit/warn lebih LEMAH dari enforce

Cek AdmissionConfiguration (plugin PodSecurity):
  psa-plugin-missing     (medium) : file admission config ada tapi
                                     plugin PodSecurity tidak terdaftar
  psa-config-malformed   (high)   : plugin PodSecurity tanpa
                                     configuration valid
  psa-defaults-missing   (medium) : cluster default enforce tidak diset
                                     (hanya namespace berlabel yang
                                     dilindungi)
  psa-defaults-invalid   (medium) : nilai default bukan level sah
  psa-defaults-below-    (medium) : default lebih lemah dari
  minimum                           --min-enforce
  psa-exempt-namespace-  (medium) : exemptions.namespaces memuat
  unknown                           namespace di luar daftar sistem
                                     (exempt = tanpa batas, wajib owner)
  psa-exempt-usernames   (low)    : exemptions.usernames tidak kosong
  psa-exempt-runtime-    (low)    : exemptions.runtimeClasses tidak
  classes                            kosong

Fail-closed: source tidak ada / tidak ada Namespace maupun
AdmissionConfiguration terkenali -> exit 2; file tidak ter-parse
tercatat di unparsed dan TIDAK diam-diam dianggap bersih. Evaluasi
LIVE (kubectl label --dry-run=server, events FailedCreate, apa pod
berjalan yang melanggar) = pemeriksaan cluster — di luar tool.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from k8s_rbac_audit import parse_documents  # noqa: E402

SCHEMA = "cyphron.psa-ns-audit/1"
MAX_FILE_BYTES = 4 * 1024 * 1024
SCAN_EXT = {".yaml", ".yml", ".json"}

PREFIX = "pod-security.kubernetes.io/"
KNOWN_SUFFIX = {"enforce", "enforce-version", "audit", "audit-version",
                "warn", "warn-version"}
LEVELS = {"privileged": 0, "baseline": 1, "restricted": 2}
VERSION_RE = re.compile(r"^v\d+\.\d+$|^latest$")
# tiga namespace bawaan Kubernetes (perluasan via --system-namespaces).
DEFAULT_SYSTEM_NS = ["kube-system", "kube-public", "kube-node-lease"]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _load_docs(source: Path) -> "tuple[list[dict], list[str]]":
    """Muat manifest dari file/dir (pola loader k8s_podsec_audit)."""
    if source.is_file():
        files = [source]
    elif source.is_dir():
        files = sorted(p for p in source.rglob("*")
                       if p.is_file() and p.suffix.lower() in SCAN_EXT)
        if not files:
            raise ValueError(f"tidak ada file {sorted(SCAN_EXT)} "
                             f"di {source}")
    else:
        raise ValueError(f"source tidak ada: {source}")

    docs: "list[dict]" = []
    unparsed: "list[str]" = []
    for f in files:
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                unparsed.append(f"{f}: terlalu besar")
                continue
            docs.extend(parse_documents(
                f.read_text(encoding="utf-8", errors="replace")))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            unparsed.append(f"{f}: {exc}")
    return docs, unparsed


def _extract(docs: "list[dict]") -> "tuple[list[dict], list[dict]]":
    """Ambil Namespace dan AdmissionConfiguration dari objek tunggal /
    List.items / array."""
    nss: "list[dict]" = []
    adm: "list[dict]" = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        kind = d.get("kind")
        if kind == "Namespace":
            nss.append(d)
        elif kind == "AdmissionConfiguration":
            adm.append(d)
        elif kind == "List" and isinstance(d.get("items"), list):
            for i in d["items"]:
                if not isinstance(i, dict):
                    continue
                if i.get("kind") == "Namespace":
                    nss.append(i)
                elif i.get("kind") == "AdmissionConfiguration":
                    adm.append(i)
    return nss, adm


def audit_namespace(ns_doc: dict, system_ns: "set[str]",
                    min_level: int) -> "list[dict]":
    findings: "list[dict]" = []
    meta = ns_doc.get("metadata", {}) if isinstance(ns_doc.get("metadata"),
                                                    dict) else {}
    name = str(meta.get("name", "?"))
    labels = meta.get("labels") if isinstance(meta.get("labels"), dict) \
        else {}

    def add(check: str, severity: str, field: str, msg: str) -> None:
        findings.append({"check": check, "severity": severity,
                         "object": f"Namespace/{name}", "field": field,
                         "message": msg})

    psa: "dict[str, str]" = {}
    for k, v in labels.items():
        ks = str(k)
        if ks.startswith(PREFIX):
            suffix = ks[len(PREFIX):]
            if suffix not in KNOWN_SUFFIX:
                add("psa-label-unknown-suffix", "medium", ks,
                    f"label prefix PSA dgn suffix '{suffix}' tidak "
                    "dikenal — typo diam-diam inert (label salah itu "
                    "tidak pernah diterapkan PSA).")
                continue
            psa[suffix] = str(v).strip()

    is_system = name in system_ns

    enforce_raw = psa.get("enforce")
    enforce_lvl: "int | None" = None
    if enforce_raw is None:
        if is_system:
            pass  # namespace sistem lazim tanpa label; dicatat di notes
        elif "audit" in psa or "warn" in psa:
            add("psa-not-enforced", "medium", "enforce",
                "audit/warn sudah diset tapi enforce TIDAK — rollout "
                "berhenti di tahap kering; pelanggaran hanya dicatat, "
                "tidak pernah ditolak.")
        else:
            add("psa-no-labels", "high", "pod-security.kubernetes.io/*",
                "namespace non-sistem tanpa label PSA apa pun — Pod "
                "Security Admission tidak menyentuh namespace ini "
                "(pod privilege apa pun diterima).")
    elif enforce_raw not in LEVELS:
        add("psa-value-invalid", "high", "enforce",
            f"nilai '{enforce_raw}' bukan level sah "
            f"{sorted(LEVELS)} — admission error saat create pod "
            "(nilai case-sensitive lowercase).")
    else:
        enforce_lvl = LEVELS[enforce_raw]
        if enforce_raw == "privileged" and not is_system:
            add("psa-enforce-privileged", "high", "enforce",
                "enforce=privileged di namespace non-sistem — tanpa "
                "batasan PSS sama sekali (kandidat kecuali sistem yang "
                "didaftarkan eksplisit).")
        elif enforce_lvl < min_level and not is_system:
            add("psa-enforce-below-minimum", "medium", "enforce",
                f"enforce={enforce_raw} lebih lemah dari minimum yang "
                f"diminta ({min_level}) — naikkan atau daftarkan "
                "namespace sbg pengecualian bermilik owner.")

    for mode in ("audit", "warn"):
        raw = psa.get(mode)
        if raw is None:
            continue
        if raw not in LEVELS:
            add("psa-value-invalid", "medium", mode,
                f"nilai '{raw}' bukan level sah {sorted(LEVELS)} — "
                "kontrol mode ini mati (case-sensitive lowercase).")
        elif enforce_lvl is not None and LEVELS[raw] < enforce_lvl:
            add("psa-mode-inconsistent", "low", mode,
                f"{mode}={raw} lebih LEMAH dari enforce="
                f"{enforce_raw} — pengawas tidak sejajar penolak "
                "(mis. masuk lewat cek lain tapi warn diam).")

    vraw = psa.get("enforce-version")
    if enforce_raw is not None and vraw is None:
        add("psa-version-unpinned", "low", "enforce-version",
            "enforce tanpa enforce-version — level ikut 'latest' saat "
            "upgrade cluster (versi baru = definisi cek bisa berubah).")
    if vraw is not None and not VERSION_RE.match(vraw):
        add("psa-version-invalid", "medium", "enforce-version",
            f"nilai '{vraw}' bukan format vN.N atau 'latest' — label "
            "versi tidak terbaca admission.")
    return findings


def audit_admission(adm_doc: dict, system_ns: "set[str]",
                    min_level: int) -> "list[dict]":
    findings: "list[dict]" = []
    name = str((adm_doc.get("metadata") or {}).get("name", "?")) \
        if isinstance(adm_doc.get("metadata"), dict) else "?"

    def add(check: str, severity: str, field: str, msg: str) -> None:
        findings.append({"check": check, "severity": severity,
                         "object": f"AdmissionConfiguration/{name}",
                         "field": field, "message": msg})

    plugins = adm_doc.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        add("psa-config-malformed", "high", "plugins",
            "plugins bukan daftar terisi — file admission config "
            "tidak bisa dievaluasi (fail-closed).")
        return findings
    psa_plugin = None
    for pl in plugins:
        if isinstance(pl, dict) and str(pl.get("name", "")) == "PodSecurity":
            psa_plugin = pl
    if psa_plugin is None:
        add("psa-plugin-missing", "medium", "plugins",
            "admission config tanpa plugin 'PodSecurity' — cluster "
            "default PSA tidak di-wire (hanya namespace berlabel yang "
            "dilindungi).")
        return findings

    conf = psa_plugin.get("configuration")
    if not isinstance(conf, dict) or not conf:
        add("psa-config-malformed", "high", "configuration",
            "plugin PodSecurity tanpa configuration valid — default/"
            "exemption tidak terbaca (fail-closed).")
        return findings

    defaults = conf.get("defaults") if isinstance(conf.get("defaults"),
                                                  dict) else {}
    if not defaults or "enforce" not in defaults:
        add("psa-defaults-missing", "medium", "defaults.enforce",
            "cluster default enforce tidak diset — namespace TANPA "
            "label PSA tidak dilindungi apa pun (isi defaults.enforce "
            "di PodSecurityConfiguration).")
    else:
        val = str(defaults.get("enforce")).strip()
        if val not in LEVELS:
            add("psa-defaults-invalid", "medium", "defaults.enforce",
                f"nilai '{val}' bukan level sah {sorted(LEVELS)}.")
        elif LEVELS[val] < min_level:
            add("psa-defaults-below-minimum", "medium",
                "defaults.enforce",
                f"default enforce={val} lebih lemah dari minimum yang "
                f"diminta ({min_level}) — namespace tanpa label "
                "mewarisi postur lemah ini.")

    exempt = conf.get("exemptions") if isinstance(conf.get("exemptions"),
                                                  dict) else {}
    ns_list = exempt.get("namespaces") if isinstance(
        exempt.get("namespaces"), list) else []
    for raw in ns_list:
        n = str(raw).strip()
        if n and n not in system_ns:
            add("psa-exempt-namespace-unknown", "medium",
                "exemptions.namespaces",
                f"'{n}' di luar daftar namespace sistem yang diketahui "
                "— exempt = admission TANPA batas untuk namespace itu "
                "(wajib owner + justifikasi; daftarkan sbg sistem bila "
                "memang sah).")
    if isinstance(exempt.get("usernames"), list) \
            and exempt.get("usernames"):
        add("psa-exempt-usernames", "low", "exemptions.usernames",
            f"{len(exempt.get('usernames'))} username di-exempt dari "
            "PSA — review berkala (akun itu bisa create pod apa pun).")
    if isinstance(exempt.get("runtimeClasses"), list) \
            and exempt.get("runtimeClasses"):
        add("psa-exempt-runtimeclasses", "low", "exemptions.runtimeClasses",
            f"{len(exempt.get('runtimeClasses'))} runtimeClass di-exempt "
            "— runtime khusus bisa membawa pod di luar PSS.")
    return findings


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit offline label Pod Security Admission pada "
                    "manifest Namespace + AdmissionConfiguration, nol "
                    "jaringan.")
    ap.add_argument("--source", required=True,
                    help="file atau direktori manifest (YAML subset/JSON)")
    ap.add_argument("--min-enforce", default="baseline",
                    choices=["privileged", "baseline", "restricted"],
                    help="level enforce minimum utk namespace "
                         "non-sistem (default baseline)")
    ap.add_argument("--system-namespaces", default="",
                    help="tambahan namespace sistem (pisah koma) yang "
                         "dikecualikan dari cek enforce/minimum")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    system_ns = set(DEFAULT_SYSTEM_NS) | {
        n.strip() for n in args.system_namespaces.split(",") if n.strip()}
    min_level = LEVELS[args.min_enforce]

    try:
        docs, unparsed = _load_docs(Path(args.source))
    except (ValueError, OSError) as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    nss, adm = _extract(docs)
    if not nss and not adm:
        print(json.dumps({"schema": SCHEMA, "error":
                          "tidak ada Namespace / AdmissionConfiguration "
                          "terkenali (fail-closed — bukti kosong bukan "
                          "'bersih')"}), file=sys.stderr)
        return 2

    findings: "list[dict]" = []
    for d in nss:
        findings += audit_namespace(d, system_ns, min_level)
    for d in adm:
        findings += audit_admission(d, system_ns, min_level)

    threshold = SEVERITY_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    summary = {
        "namespaces_audited": len(nss),
        "admission_configs_audited": len(adm),
        "min_enforce": args.min_enforce,
        "system_namespaces": sorted(system_ns),
        "findings": len(findings),
        "by_severity": {
            s: sum(1 for f in findings if f["severity"] == s)
            for s in ("high", "medium", "low")
        },
        "unparsed": unparsed,
    }
    notes = [
        "audit statis label PSA pada manifest Namespace + "
        "AdmissionConfiguration (GitOps) — spec pod vs profil PSS = "
        "k8s_podsec_audit (B22), RBAC = k8s_rbac_audit, NetworkPolicy "
        "= netpol_audit (B23), log API server jalan = "
        "k8s_audit_triage.",
        "nilai label PSA case-sensitive lowercase (privileged/baseline/"
        "restricted); versi = vN.N atau latest.",
        "namespace sistem default = tiga bawaan Kubernetes "
        "(kube-system, kube-public, kube-node-lease); perluas via "
        "--system-namespaces bila env punya (mis. calico-system, "
        "gatekeeper-system, monitoring).",
        "evaluasi LIVE (kubectl label --dry-run=server, events "
        "FailedCreate, pod berjalan yang melanggar level baru) = "
        "pemeriksaan cluster — di luar tool.",
    ]
    if unparsed:
        notes.append("ada file/objek tidak ter-parse — hasil TIDAK "
                     "menyatakan 'bersih' atas berkas yang gagal "
                     "dibaca (fail-closed).")
    report = {
        "schema": SCHEMA,
        "summary": summary,
        "findings": sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0),
                           f["object"], f["check"])),
        "notes": notes,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
