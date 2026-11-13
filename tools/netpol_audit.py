r"""[AUDIT: read-only] netpol_audit — audit OFFLINE manifest Kubernetes
NetworkPolicy (networking.k8s.io/v1, upstream/CNI-portable): linter
statis yang menjawab "postur segmentasi east-west mana yang BERONGGA"
sebelum apply / dari repo GitOps.

Input -> mekanisme -> output:
  - Input   : --source FILE/DIR (YAML subset atau JSON, pola loader
              k8s_rbac_audit.parse_documents) + --expect-ns (namespace
              yang WAJIB punya policy; kosong = infer dari policy
              yang terlihat) + --fail-on.
  - Mekanisme: ekstrak NetworkPolicy (objek tunggal / List.items /
              array), normalisasi artefak parser YAML-subset (inline
              '{}' -> peta kosong), kelompokkan per namespace, cek
              deterministik per-policy dan per-namespace.
  - Output  : temuan {check, severity, namespace, policy, direction,
              message} + summary + notes.

Cek (semantik k8s yang dienkode eksplisit):
  deny-all-noop          (high)   : podSelector kosong TANPA policyTypes
                                     DAN tanpa rule — policy tidak
                                     mengenforce apa pun (inference
                                     spec: tanpa key ingress/egress,
                                     policyTypes tidak diinfer) —
                                     "deny-all" yang diam-diam mati
  allow-all-rule         (high)   : rule ingress tanpa/from-kosong atau
                                     egress tanpa/to-kosong = allow
                                     semua sumber/tujuan
  allow-all-peer         (high)   : peer namespaceSelector {} (semua
                                     namespace) atau peer {} kosong
  select-all-on-select-  (high)   : peer podSelector {} pada policy
  all                               ber-podSelector kosong = policy
                                     meliputi SEMUA pod + rule allow
                                     semua pod namespace = deny baseline
                                     kalah total untuk arah itu
  allow-all-pods         (medium) : peer podSelector {} pada policy
                                     ber-podSelector spesifik (lebar,
                                     tapi terbatas pod terpilih)
  policytypes-mismatch   (high)   : rule egress/ingress ada tapi tidak
                                     di policyTypes eksplisit — rule
                                     MATI (tidak dienforce)
  policytypes-missing    (medium) : policyTypes tidak eksplisit
                                     (inference spec; drift lintas CNI)
  no-policy-namespace    (high)   : namespace di --expect-ns tanpa
                                     policy sama sekali
  deny-ingress-missing   (medium) : namespace terlihat punya policy
                                     tapi tidak ada baseline deny
                                     ingress (podSelector kosong +
                                     policyTypes Ingress)
  deny-egress-missing    (medium) : idem arah egress
  dns-egress-missing     (medium) : namespace punya policy Egress tapi
                                     tidak ada satu pun rule yang
                                     mengizinkan port 53 UDP/TCP
                                     (discovery pecah; tim biasanya
                                     "memperbaiki" dgn allow-all = batal)
  wide-open-ipblock      (medium) : ipBlock 0.0.0.0/0 atau ::/0 tanpa
                                     except (egress ke internet semua /
                                     ingress dari semua IP)
  metadata-egress-       (medium) : ipBlock wide-open tanpa except
  exposed                           169.254.169.254/32 dan
                                     100.100.100.200/32 — jalur SSRF ke
                                     cloud metadata (cf. seksi 109
                                     docs/PORT-AGENT-METHODS.md)
  ipblock-cidr-invalid   (medium) : cidr tidak valid (fail-closed, bukan
                                     diabaikan)

Fail-closed: source tidak ada / tidak ada NetworkPolicy terkenali ->
exit 2; file tidak ter-parse tercatat di unparsed dan TIDAK diam-diam
dianggap bersih. Verifikasi enforcement sesungguhnya (CNI benar-benar
menolak) = kubectl run test-pod di lab berizin — di luar tool.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from k8s_rbac_audit import parse_documents  # noqa: E402

SCHEMA = "secai.netpol-audit/1"
MAX_FILE_BYTES = 4 * 1024 * 1024
SCAN_EXT = {".yaml", ".yml", ".json"}

# CIDR "semua" yang menandai rule allow-world.
WIDE_CIDRS = {"0.0.0.0/0", "::/0"}
# endpoint cloud metadata yang wajib di-except pada egress wide-open
# (AWS/GCP 169.254.169.254, Azure 100.100.100.200).
METADATA_EXCEPTS = {"169.254.169.254/32", "100.100.100.200/32"}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _empty_map(v: object) -> bool:
    """Peta kosong — termasuk artefak parser YAML-subset: inline
    ``{}`` tiba sebagai string '{}', key tanpa nilai tiba sebagai
    {} (None tidak: parser null -> {}). Semantik k8s: selector
    kosong = cocok SEMUA."""
    if v is None:
        return True
    if isinstance(v, dict):
        return len(v) == 0
    if isinstance(v, str) and v.strip() == "{}":
        return True
    return False


def _targets_all_pods(spec: dict) -> bool:
    """podSelector kosong/absen = policy berlaku utk SEMUA pod di
    namespace-nya."""
    return _empty_map(spec.get("podSelector"))


def _peer_class(peer: object) -> str:
    """Klasifikasi satu peer from/to:
    'all'     = semua sumber/tujuan (peer kosong, nsSelector {},
                nsSelector {} + podSelector {})
    'ns-all'  = semua pod namespace ini (podSelector {} tanpa nsSelector)
    'ip'      = ipBlock
    'scoped'  = selector spesifik / tidak dikenal"""
    if _empty_map(peer):
        return "all"
    if not isinstance(peer, dict):
        return "scoped"
    if "ipBlock" in peer:
        return "ip"
    ns = peer.get("namespaceSelector")
    ps = peer.get("podSelector")
    ns_present = "namespaceSelector" in peer
    ns_all = ns_present and _empty_map(ns)
    ps_all = "podSelector" in peer and _empty_map(ps)
    if ns_present and ns_all and (ps is None or ps_all):
        return "all"
    if ns_all and ps is not None and not ps_all:
        return "scoped"  # nsSelector {} + podSelector spesifik
    if not ns_present and ps_all:
        return "ns-all"
    return "scoped"


def _effective_types(spec: dict) -> "set[str]":
    """Jenis policy efektif: eksplisit policyTypes, atau inference
    spec publik (Ingress jika spec.ingress ada, Egress jika
    spec.egress ada). key kosong/absen TIDAK diinfer."""
    pt = spec.get("policyTypes")
    if isinstance(pt, list) and pt:
        return {str(t).strip() for t in pt if str(t).strip()}
    out: "set[str]" = set()
    if isinstance(spec.get("ingress"), list):
        out.add("Ingress")
    if isinstance(spec.get("egress"), list):
        out.add("Egress")
    return out


def _ports_allow(rule: dict, port_num: int, port_name: str) -> bool:
    """Apakah satu rule mengizinkan port tertentu: ports absen = semua
    port; entry port cocok bila nomor sama ATAU nama sama (named port,
    mis. 'dns'), protocol abai (absen = TCP+UDP)."""
    ports = rule.get("ports")
    if ports is None:
        return True
    if not isinstance(ports, list):
        return True
    for p in ports:
        if not isinstance(p, dict):
            continue
        raw = p.get("port")
        if raw is None:
            return True  # entry tanpa port = semua
        # parser YAML-subset mengembalikan skalar sbg string ('53')
        try:
            if int(str(raw).strip().strip("'\"")) == port_num:
                return True
        except (TypeError, ValueError):
            pass
        if isinstance(raw, str) and raw.strip().lower() == port_name:
            return True
    return False


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


def _extract_policies(docs: "list[dict]") -> "list[dict]":
    """Ambil NetworkPolicy dari objek tunggal / List.items / array."""
    out: "list[dict]" = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        if d.get("kind") == "NetworkPolicy":
            out.append(d)
        elif d.get("kind") == "List" and isinstance(d.get("items"), list):
            out.extend(i for i in d["items"] if isinstance(i, dict)
                       and i.get("kind") == "NetworkPolicy")
    return out


def _norm_excepts(block: dict) -> "list[str]":
    exc = block.get("except")
    if not isinstance(exc, list):
        return []
    return [str(e).strip() for e in exc if str(e).strip()]


def _cidr_valid(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def audit_policy(pol: dict) -> "list[dict]":
    """Cek deterministik satu NetworkPolicy (per-policy)."""
    findings: "list[dict]" = []
    spec = pol.get("spec") if isinstance(pol.get("spec"), dict) else {}
    meta = pol.get("metadata", {}) if isinstance(pol.get("metadata"),
                                                 dict) else {}
    name = str(meta.get("name", "?"))
    ns = str(meta.get("namespace", "default"))

    def add(check: str, severity: str, direction: str, msg: str) -> None:
        findings.append({"check": check, "severity": severity,
                         "namespace": ns, "policy": name,
                         "direction": direction, "message": msg})

    targets_all = _targets_all_pods(spec)
    etypes = _effective_types(spec)
    has_pt = bool(etypes) and isinstance(spec.get("policyTypes"), list) \
        and bool(spec.get("policyTypes"))

    # ---- policyTypes
    if not isinstance(spec.get("policyTypes"), list) \
            or not spec.get("policyTypes"):
        if "ingress" not in spec and "egress" not in spec:
            add("deny-all-noop", "high", "-",
                "podSelector kosong TANPA policyTypes DAN tanpa rule "
                "ingress/egress — inference spec tidak memasukkan "
                "policyTypes apa pun sehingga policy TIDAK mengenforce "
                "apa pun; 'default-deny' yang diam-diam mati. Tulis "
                "eksplisit policyTypes: [Ingress, Egress] (tanpa rule = "
                "deny semuanya).")
        else:
            add("policytypes-missing", "medium", "-",
                "policyTypes tidak eksplisit — spec diinfer dari key "
                "ingress/egress; eksplisit = anti-drift lintas CNI "
                "(dan menandai niat deny eksplisit).")

    for direction, rules_key in (("ingress", "ingress"),
                                 ("egress", "egress")):
        rules = spec.get(rules_key)
        cap = direction.capitalize()
        rules_list = rules if isinstance(rules, list) else None
        if rules_list and cap not in etypes:
            add("policytypes-mismatch", "high", direction,
                f"{len(rules_list)} rule {direction} ada di spec tapi "
                f"'{cap}' tidak ada di policyTypes — rule MATI (tidak "
                "dienforce; traffic arah ini tidak dikontrol).")
        if not rules_list:
            continue
        for ri, rule in enumerate(rules_list):
            if not isinstance(rule, dict):
                continue
            peer_key = "from" if direction == "ingress" else "to"
            peers = rule.get(peer_key)
            if peers is None or (isinstance(peers, list)
                                 and not peers):
                add("allow-all-rule", "high", direction,
                    f"rule #{ri}: '{peer_key}' "
                    f"{'tidak ada' if peers is None else 'kosong'} — "
                    f"per spec cocok SEMUA sumber/tujuan (allow-world).")
                continue
            for pi, peer in enumerate(peers):
                klass = _peer_class(peer)
                if klass == "all":
                    add("allow-all-peer", "high", direction,
                        f"rule #{ri} peer #{pi}: selector kosong / "
                        "namespaceSelector {} = sumber/tujuan tidak "
                        "dibatasi.")
                elif klass == "ns-all":
                    if targets_all:
                        add("select-all-on-select-all", "high",
                            direction,
                            f"rule #{ri} peer #{pi}: podSelector {{}} pada "
                            "policy ber-podSelector kosong — policy "
                            "meliputi SEMUA pod namespace dan rule "
                            "mengizinkan SEMUA pod = deny baseline arah "
                            f"{direction} kalah total.")
                    else:
                        add("allow-all-pods", "medium", direction,
                            f"rule #{ri} peer #{pi}: podSelector {{}} — "
                            "semua pod namespace diizinkan pada pod "
                            "terpilih (lebar; review niat).")
                elif klass == "ip":
                    block = peer.get("ipBlock")
                    if not isinstance(block, dict):
                        continue
                    cidr = str(block.get("cidr", "")).strip()
                    if not cidr or not _cidr_valid(cidr):
                        add("ipblock-cidr-invalid", "medium", direction,
                            f"rule #{ri} peer #{pi}: ipBlock cidr "
                            f"'{cidr}' tidak valid (traffic tidak akan "
                            "dicocokkan; fail-closed).")
                        continue
                    excepts = _norm_excepts(block)
                    if cidr in WIDE_CIDRS:
                        if not excepts:
                            add("wide-open-ipblock", "medium", direction,
                                f"rule #{ri} peer #{pi}: ipBlock {cidr} "
                                "tanpa except — arah "
                                f"{direction} ke/dari semua IP.")
                            if direction == "egress" and not (
                                METADATA_EXCEPTS & set(excepts)):
                                add("metadata-egress-exposed", "medium",
                                    direction,
                                    f"rule #{ri} peer #{pi}: egress "
                                    f"{cidr} tanpa except "
                                    f"{sorted(METADATA_EXCEPTS)} — pod "
                                    "bisa mencapai cloud metadata "
                                    "(SSRF -> kredensial).")
                        elif direction == "egress" and not (
                                METADATA_EXCEPTS & set(excepts)):
                            add("metadata-egress-exposed", "medium",
                                direction,
                                f"rule #{ri} peer #{pi}: egress {cidr} "
                                "punya except tapi TIDAK menutup "
                                f"{sorted(METADATA_EXCEPTS)} — jalur "
                                "cloud metadata tetap terbuka.")
    return findings


def audit_namespaces(policies: "list[dict]",
                     expect_ns: "list[str]") -> "list[dict]":
    """Cek per-namespace: baseline deny, DNS egress, expect coverage."""
    findings: "list[dict]" = []
    by_ns: "dict[str, list[dict]]" = {}
    for pol in policies:
        spec = pol.get("spec") if isinstance(pol.get("spec"), dict) \
            else {}
        meta = pol.get("metadata", {}) if isinstance(pol.get("metadata"),
                                                     dict) else {}
        ns = str(meta.get("namespace", "default"))
        by_ns.setdefault(ns, []).append(pol)

    def add(check: str, severity: str, ns: str, msg: str) -> None:
        findings.append({"check": check, "severity": severity,
                         "namespace": ns, "policy": "-",
                         "direction": "-", "message": msg})

    for ns in sorted(expect_ns):
        if ns not in by_ns:
            add("no-policy-namespace", "high", ns,
                "namespace di --expect-ns tanpa NetworkPolicy sama "
                "sekali — east-west tidak dikontrol.")

    for ns, pols in sorted(by_ns.items()):
        has_deny_in = any(
            _targets_all_pods(p.get("spec", {})
                              if isinstance(p.get("spec"), dict) else {})
            and "Ingress" in _effective_types(
                p.get("spec", {}) if isinstance(p.get("spec"), dict)
                else {})
            for p in pols)
        has_deny_eg = any(
            _targets_all_pods(p.get("spec", {})
                              if isinstance(p.get("spec"), dict) else {})
            and "Egress" in _effective_types(
                p.get("spec", {}) if isinstance(p.get("spec"), dict)
                else {})
            for p in pols)
        if not has_deny_in:
            add("deny-ingress-missing", "medium", ns,
                f"{len(pols)} policy di namespace ini tapi tidak ada "
                "baseline deny ingress (podSelector kosong + "
                "policyTypes Ingress) — pod tanpa policy khusus "
                "menerima traffic dari mana saja.")
        if not has_deny_eg:
            add("deny-egress-missing", "medium", ns,
                f"{len(pols)} policy di namespace ini tapi tidak ada "
                "baseline deny egress (podSelector kosong + "
                "policyTypes Egress) — pod tanpa policy khusus bisa "
                "keluar ke mana saja.")

        # DNS: namespace yang mulai membatasi egress wajib punya jalur
        # port 53 (acuan internal Step 2; discovery pecah tanpa itu).
        egress_restricted = any(
            "Egress" in _effective_types(
                p.get("spec", {}) if isinstance(p.get("spec"), dict)
                else {})
            for p in pols)
        if egress_restricted:
            dns_ok = False
            for p in pols:
                spec = p.get("spec") if isinstance(p.get("spec"), dict) \
                    else {}
                rules = spec.get("egress")
                if not isinstance(rules, list):
                    continue
                for rule in rules:
                    if isinstance(rule, dict) and \
                            _ports_allow(rule, 53, "dns"):
                        dns_ok = True
                        break
                if dns_ok:
                    break
            if not dns_ok:
                add("dns-egress-missing", "medium", ns,
                    "namespace punya policy Egress tapi tidak ada satu "
                    "pun rule yang mengizinkan port 53 (UDP/TCP atau "
                    "named 'dns' atau rule tanpa ports) — service "
                    "discovery pecah; workaround 'allow-all' biasanya "
                    "mengikuti dan membatalkan postur egress.")
    return findings


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit offline manifest Kubernetes NetworkPolicy "
                    "(upstream v1) — postur default-deny/egress, nol "
                    "jaringan.")
    ap.add_argument("--source", required=True,
                    help="file atau direktori manifest (YAML subset/JSON)")
    ap.add_argument("--expect-ns", default="",
                    help="namespace yang WAJIB punya policy, pisah "
                         "koma (kosong = infer dari policy terlihat)")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    expect_ns = [n.strip() for n in args.expect_ns.split(",") if n.strip()]

    try:
        docs, unparsed = _load_docs(Path(args.source))
    except (ValueError, OSError) as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    policies = _extract_policies(docs)
    if not policies:
        print(json.dumps({"schema": SCHEMA, "error":
                          "tidak ada NetworkPolicy terkenali "
                          "(fail-closed — bukti kosong bukan 'bersih')"}),
              file=sys.stderr)
        return 2

    findings: "list[dict]" = []
    for pol in policies:
        findings += audit_policy(pol)
    findings += audit_namespaces(policies, expect_ns)

    threshold = SEVERITY_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    ns_seen = sorted({str((p.get("metadata") or {}).get("namespace",
                                                   "default"))
                      for p in policies})
    summary = {
        "policies_audited": len(policies),
        "namespaces": ns_seen,
        "expect_ns": expect_ns,
        "findings": len(findings),
        "by_severity": {
            s: sum(1 for f in findings if f["severity"] == s)
            for s in ("high", "medium", "low")
        },
        "unparsed": unparsed,
    }
    notes = [
        "audit statis NetworkPolicy upstream networking.k8s.io/v1 — "
        "CRD vendor (Calico GlobalNetworkPolicy/Tier, Cilium "
        "CiliumNetworkPolicy) di luar scope; ranah tetangga: RBAC = "
        "k8s_rbac_audit, spec pod PSS = k8s_podsec_audit, log API "
        "server jalan = k8s_audit_triage.",
        "semantik k8s yang dienkode: rule tanpa/kosong from|to, peer "
        "kosong, namespaceSelector {} = allow semua; ports absen = "
        "semua port; policyTypes kosong TIDAK diinfer (policy noop); "
        "podSelector kosong = SEMUA pod namespace.",
        "podSelector matchExpressions dianggap scoped — kecocokan "
        "selector vs label workload nyata butuh data cluster (verifikasi "
        "enforcement = kubectl test-pod di lab berizin, ops).",
        "ipBlock except dicocokkan string CIDR persis (169.254.169.254"
        "/32, 100.100.100.200/32) — subset/superset CIDR tidak "
        "dihitung.",
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
                           f["namespace"], f["policy"], f["check"])),
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
