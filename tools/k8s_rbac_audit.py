"""[AUDIT: read-only] k8s_rbac_audit — audit OFFLINE manifest RBAC
Kubernetes: hak berlebih, jalur eskalasi, binding berbahaya.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/auditing-kubernetes-cluster-rbac' (#0267) — dan menghitung
juga kelas "siapa bisa eskalasi" dari 'auditing-kubernetes-rbac-
privilege-escalation' (#0268) (atribusi ide; lisensi sumber Apache-2.0).
Dibangun from scratch TANPA kode sumber itu. TIDAK menjalankan kubectl
dan TIDAK menyentuh cluster: input = manifest RBAC lokal (YAML subset
atau JSON `kubectl get ... -o json`) — audit statis sebelum apply /
dari repo GitOps; pemeriksaan live-cluster tetap milik kubectl/who-can.

Kelas temuan (deterministik, zero-FP — hanya bentuk eksplisit):
  wildcard-all      verbs ["*"] + resources ["*"] (critical)
  wildcard-verbs    verbs ["*"] saja (high)
  wildcard-resources resources ["*"] saja (high)
  secrets-read      secrets + get/list/watch/* (high)
  pods-exec         pods/exec|attach|pods/* + create/* (high)
  escalate-verb     verbs escalate pada roles/clusterroles (critical)
  bind-verb         verbs bind pada roles/clusterroles (critical)
  impersonate       verbs impersonate (critical)
  sa-token-create   create serviceaccounts/token (critical)
  binding-cluster-admin  roleRef cluster-admin (critical bila subject
                    ServiceAccount/group system:*-authenticated, else high)
  binding-unauth    subject system:unauthenticated (critical)
  default-sa-bound  ServiceAccount "default" terikat role berisiko (high)

Fail-closed:
  - file/dir tidak ada, tidak ada manifest dikenali  -> exit 2
  - YAML/JSON tidak ter-parse                        -> tercatat
    unparsed, TIDAK PERNAH dihitung "bersih"
  - role bawaan (nama diawali "system:") dilewati dari flagging
    (built-in, bukan keputusan operator) — dihitung di meta
  - resourceNames tetap diperiksa; batasannya dicatat di detail

Ringkasan kemampuan per subject (jawaban "siapa bisa eskalasi") ikut
dihitung dari resolusi roleRef binding -> role.

Pemakaian:
  python tools/k8s_rbac_audit.py --source k8s/ --out rbac.json
  python tools/k8s_rbac_audit.py --source rbac.yaml --fail-on high
Exit: 0 selesai; 1 ada temuan >= --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.k8s-rbac-audit/1"
RBAC_KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
SCAN_EXT = {".yaml", ".yml", ".json"}
MAX_FILE_BYTES = 4 * 1024 * 1024

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

ESCALATION_CODES = {"wildcard-all", "escalate-verb", "bind-verb",
                    "impersonate", "sa-token-create"}


# ------------------------------------------------- YAML subset parser
def _strip_comment(line: str) -> str:
    """Buang komentar '#' di luar tanda kutip (aman untuk subset RBAC)."""
    out = []
    quote: "str | None" = None
    for i, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(tok: str) -> str:
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        return tok[1:-1]
    return tok


def _inline_value(raw: str) -> "list[str] | str":
    """Nilai skalar atau inline list [a, b] (subset manifest RBAC)."""
    raw = raw.strip()
    if raw.startswith("["):
        if not raw.endswith("]"):
            raise ValueError(f"inline list tidak ditutup: {raw!r}")
        body = raw[1:-1].strip()
        if not body:
            return []
        return [_scalar(p) for p in body.split(",")]
    return _scalar(raw)


def _parse_map(lines: "list[tuple[int, str]]", i: int,
               indent: int) -> "tuple[dict, int]":
    obj: dict = {}
    while i < len(lines):
        ind, content = lines[i]
        if ind < indent:
            break
        if ind > indent:
            raise ValueError(f"indentasi tak terduga: {content!r}")
        m = re.match(r"^([^:]+):\s*(.*)$", content)
        if not m:
            raise ValueError(f"baris tak ter-parse: {content!r}")
        key, val = m.group(1).strip(), m.group(2).strip()
        if val:
            obj[key] = _inline_value(val)
            i += 1
            continue
        nxt = lines[i + 1] if i + 1 < len(lines) else None
        if nxt and (nxt[0] > indent or nxt[1] == "-"
                    or nxt[1].startswith("- ")):
            obj[key], i = _parse_block(lines, i + 1, nxt[0])
        else:
            obj[key] = {}
            i += 1
    return obj, i


def _parse_list(lines: "list[tuple[int, str]]", i: int,
                indent: int) -> "tuple[list, int]":
    items: list = []
    while i < len(lines):
        ind, content = lines[i]
        if ind != indent or not (content == "-"
                                 or content.startswith("- ")):
            break  # akhir list ini (kembali ke map induk / list lain)
        if content == "-":
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                val, i = _parse_block(lines, i + 1, lines[i + 1][0])
                items.append(val)
            else:
                items.append(None)
                i += 1
            continue
        rest = content[2:].strip()
        m = re.match(r"^([^:]+):\s*(.*)$", rest)
        if m is None:
            items.append(_inline_value(rest))
            i += 1
            continue
        item: dict = {}
        key, val = m.group(1).strip(), m.group(2).strip()
        if val:
            item[key] = _inline_value(val)
            i += 1
        else:
            nxt = lines[i + 1] if i + 1 < len(lines) else None
            if nxt and (nxt[0] > indent or nxt[1] == "-"
                        or nxt[1].startswith("- ")):
                item[key], i = _parse_block(lines, i + 1, nxt[0])
            else:
                item[key] = {}
                i += 1
        # key kelanjutan milik item ini: indent > indent dash, bukan dash
        while i < len(lines):
            ind2, content2 = lines[i]
            if ind2 <= indent or content2 == "-" \
                    or content2.startswith("- "):
                break
            m2 = re.match(r"^([^:]+):\s*(.*)$", content2)
            if not m2:
                raise ValueError(f"baris tak ter-parse: {content2!r}")
            k2, v2 = m2.group(1).strip(), m2.group(2).strip()
            if v2:
                item[k2] = _inline_value(v2)
                i += 1
                continue
            nxt2 = lines[i + 1] if i + 1 < len(lines) else None
            if nxt2 and (nxt2[0] > ind2 or nxt2[1] == "-"
                         or nxt2[1].startswith("- ")):
                item[k2], i = _parse_block(lines, i + 1, nxt2[0])
            else:
                item[k2] = {}
                i += 1
        items.append(item)
    return items, i


def _parse_block(lines: "list[tuple[int, str]]", i: int,
                 indent: int) -> "tuple[object, int]":
    content = lines[i][1]
    if content == "-" or content.startswith("- "):
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_yaml_stream(text: str) -> "list[dict]":
    """Parse YAML SUBSET multi-dokumen (bentuk manifest k8s umum).

    Mendukung: map per-indentasi, list `- ` (termasuk item dash pada
    indentasi sama dengan key induk), inline list [a, b], kutip, dan
    komentar. Struktur di luar subset -> ValueError (fail-closed);
    ini BUKAN parser YAML umum.
    """
    docs: list[dict] = []
    lines: "list[tuple[int, str]]" = []

    def flush() -> None:
        nonlocal lines
        if not lines:
            return
        value, _ = _parse_block(lines, 0, lines[0][0])
        if not isinstance(value, dict):
            raise ValueError("akar dokumen bukan map")
        docs.append(value)
        lines = []

    for raw_line in text.splitlines():
        line = _strip_comment(raw_line.replace("\t", "  "))
        if not line.strip():
            continue
        if line.strip() == "---":
            flush()
            continue
        lines.append((len(line) - len(line.lstrip()), line.strip()))
    flush()
    return docs


def parse_documents(text: str) -> "list[dict]":
    """Parse YAML subset -> daftar dokumen; JSON diteruskan bila cocok."""
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        data = json.loads(stripped)
        if isinstance(data, dict):
            return [data]
        return [d for d in data if isinstance(d, dict)]
    return [d for d in _parse_yaml_stream(text) if isinstance(d, dict)]


# ------------------------------------------------------------ analisis
def _extract_manifests(docs: "list[dict]") -> "list[dict]":
    """Ambil objek RBAC dari: objek tunggal / List.items / array."""
    out: list[dict] = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        kind = d.get("kind")
        if kind in RBAC_KINDS:
            out.append(d)
        elif kind == "List" and isinstance(d.get("items"), list):
            out.extend(i for i in d["items"] if isinstance(i, dict)
                       and i.get("kind") in RBAC_KINDS)
    return out


def _risky_rules(rules: "list | None") -> "list[dict]":
    """Klasifikasi aturan berisiko dari satu Role/ClusterRole."""
    out: list[dict] = []
    for ri, rule in enumerate(rules or []):
        if not isinstance(rule, dict):
            continue
        verbs = [str(v) for v in rule.get("verbs") or []]
        resources = [str(r) for r in rule.get("resources") or []]
        names = [str(n) for n in rule.get("resourceNames") or []]
        v_all = "*" in verbs
        r_all = "*" in resources
        v_set = set(verbs)
        r_set = {r.lower() for r in resources}

        def has_res(*targets: str) -> bool:
            return bool(r_set & set(targets)) or r_all

        found: "list[tuple[str, str, str]]" = []
        god_mode = v_all and r_all
        if god_mode:
            # wildcard penuh sudah mencakup semua kelas di bawah —
            # satu temuan critical, tanpa pengulangan berulir
            found.append(("wildcard-all", "critical",
                          "verbs ['*'] + resources ['*']"))
        else:
            if v_all:
                found.append(("wildcard-verbs", "high",
                              f"verbs ['*'] pada resources {resources}"))
            if r_all:
                found.append(("wildcard-resources", "high",
                              f"resources ['*'] pada verbs {verbs}"))
            if has_res("secrets") and (v_all or
                                       v_set & {"get", "list", "watch"}):
                detail = "bisa membaca secrets"
                if names:
                    detail += f" (dibatasi resourceNames: {names})"
                found.append(("secrets-read", "high", detail))
            exec_res = r_set & {"pods/exec", "pods/attach", "pods/*"}
            if (exec_res or r_all) and (v_all or "create" in v_set):
                detail = (f"exec/attach ke pod "
                          f"({sorted(exec_res) or ['*']})")
                if names:
                    detail += f" (resourceNames: {names})"
                found.append(("pods-exec", "high", detail))
            if ("serviceaccounts/token" in r_set or r_all) and \
                    (v_all or "create" in v_set):
                found.append(("sa-token-create", "critical",
                              "create serviceaccounts/token — minta "
                              "token service account lain"))
        if "escalate" in v_set and has_res("roles", "clusterroles"):
            found.append(("escalate-verb", "critical",
                          "verbs escalate pada roles/clusterroles — "
                          "bisa memberi diri izin apa pun"))
        if "bind" in v_set and has_res("roles", "clusterroles"):
            found.append(("bind-verb", "critical",
                          "verbs bind pada roles/clusterroles — bisa "
                          "mengikat diri ke role apa pun termasuk "
                          "cluster-admin"))
        if "impersonate" in v_set:
            found.append(("impersonate", "critical",
                          f"verbs impersonate pada {resources or ['*']}"))
        for code, sev, detail in found:
            out.append({"rule_index": ri, "code": code,
                        "severity": sev, "detail": detail,
                        "verbs": verbs, "resources": resources})
    return out


def _subject_str(s: dict) -> str:
    kind = s.get("kind", "?")
    name = s.get("name", "?")
    ns = s.get("namespace")
    return f"{kind}:{name}" + (f"@{ns}" if ns else "")


def audit(manifests: "list[dict]") -> dict:
    """Analisis daftar manifest RBAC -> laporan fail-closed."""
    roles: dict[tuple[str, str], dict] = {}     # (kind, name) -> obj
    bindings: list[dict] = []
    builtin_skipped = 0
    for m in manifests:
        name = str((m.get("metadata") or {}).get("name") or "")
        kind = str(m.get("kind") or "")
        if not name:
            continue
        if name.startswith("system:"):
            builtin_skipped += 1
            continue
        if kind in ("Role", "ClusterRole"):
            roles[(kind, name)] = m
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            bindings.append(m)

    findings: list[dict] = []
    # (kind, name) -> set kode kemampuan berisiko dari role itu
    caps: dict[tuple[str, str], set] = {}

    def add_finding(sev: str, code: str, where: str, detail: str,
                    **extra) -> None:
        findings.append({"severity": sev, "code": code, "where": where,
                         "detail": detail, **extra})

    # 1) role/clusterrole berisiko
    for (kind, name), m in sorted(roles.items()):
        rules = m.get("rules")
        for r in _risky_rules(rules if isinstance(rules, list)
                              else None):
            add_finding(r["severity"], r["code"], f"{kind}/{name}",
                        r["detail"], verbs=r["verbs"],
                        resources=r["resources"])
            caps.setdefault((kind, name), set()).add(r["code"])

    # 2) binding berbahaya + resolusi ke role
    for b in bindings:
        kind = str(b.get("kind") or "")
        name = str((b.get("metadata") or {}).get("name") or "")
        role_ref = b.get("roleRef") if isinstance(
            b.get("roleRef"), dict) else {}
        ref_name = str(role_ref.get("name") or "")
        ref_kind = str(role_ref.get("kind") or "")
        subjects = b.get("subjects") if isinstance(
            b.get("subjects"), list) else []
        subj_strs = [_subject_str(s) for s in subjects
                     if isinstance(s, dict)]
        is_unauth = any("system:unauthenticated" in s
                        for s in subj_strs)
        is_authed = any(":system:authenticated" in s
                        or s == "Group:system:authenticated"
                        for s in subj_strs)
        if ref_name == "cluster-admin":
            sa_subjects = [s for s in subj_strs
                           if s.startswith("ServiceAccount:")]
            if sa_subjects or is_unauth or is_authed:
                sev = "critical"
            else:
                sev = "high"
            add_finding(sev, "binding-cluster-admin", f"{kind}/{name}",
                        f"cluster-admin -> {', '.join(subj_strs) or '?'}",
                        subjects=subj_strs)
        if is_unauth:
            add_finding("critical", "binding-unauth", f"{kind}/{name}",
                        f"{ref_name} terikat ke system:unauthenticated",
                        subjects=subj_strs)
        # default service account terikat ke role berisiko
        default_sa = [s for s in subjects if isinstance(s, dict)
                      and str(s.get("kind")) == "ServiceAccount"
                      and str(s.get("name")) == "default"]
        if ref_name == "cluster-admin":
            if default_sa:
                add_finding("high", "default-sa-bound", f"{kind}/{name}",
                            "ServiceAccount default terikat ke "
                            "cluster-admin", subjects=subj_strs)
            continue
        role = roles.get((ref_kind, ref_name)) or \
            roles.get(("ClusterRole", ref_name)) or \
            roles.get(("Role", ref_name))
        if role is None or not default_sa:
            continue
        rkind = str(role.get("kind"))
        risky = _risky_rules(role.get("rules")
                             if isinstance(role.get("rules"), list)
                             else None)
        if risky:
            add_finding("high", "default-sa-bound", f"{kind}/{name}",
                        f"ServiceAccount default terikat ke "
                        f"{rkind}/{ref_name} yang berisiko "
                        f"({risky[0]['code']})", subjects=subj_strs)

    # 3) ringkasan kemampuan per subject (siapa bisa eskalasi)
    subject_caps: list[dict] = []
    seen_sc: set[tuple] = set()
    for b in bindings:
        kind = str(b.get("kind") or "")
        name = str((b.get("metadata") or {}).get("name") or "")
        role_ref = b.get("roleRef") if isinstance(
            b.get("roleRef"), dict) else {}
        ref_name = str(role_ref.get("name") or "")
        subjects = b.get("subjects") if isinstance(
            b.get("subjects"), list) else []
        if ref_name == "cluster-admin":
            codes = {"wildcard-all"}
        else:
            role_key = None
            for key in ((str(role_ref.get("kind") or ""), ref_name),
                        ("ClusterRole", ref_name), ("Role", ref_name)):
                if key in roles:
                    role_key = key
                    break
            codes = caps.get(role_key, set()) if role_key else set()
        codes = codes & ESCALATION_CODES
        if not codes:
            continue
        for s in subjects:
            if not isinstance(s, dict):
                continue
            key = (_subject_str(s), f"{kind}/{name}")
            if key in seen_sc:
                continue
            seen_sc.add(key)
            subject_caps.append({
                "subject": key[0],
                "via": f"{key[1]} -> {ref_name}",
                "escalation": sorted(codes),
            })
    subject_caps.sort(key=lambda sc: (sc["subject"], sc["via"]))

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                 f["where"], f["code"]))
    return {
        "schema": SCHEMA,
        "manifests_total": len(manifests),
        "roles_audited": len(roles),
        "bindings_audited": len(bindings),
        "builtin_system_skipped": builtin_skipped,
        "summary": {
            "findings_total": len(findings),
            "by_severity": {k: by_sev[k] for k in sorted(
                by_sev, key=lambda s: SEV_ORDER.get(s, 9))},
        },
        "escalation_subjects": subject_caps,
        "findings": findings,
        "note": "audit statis manifest — bukan hasil evaluasi "
                "authorizer live; klaim eskalasi berlaku untuk manifest "
                "yang dianalisis",
    }


# ----------------------------------------------------------- input/dir
def _load_files(source: Path) -> "tuple[list[dict], list[str]]":
    manifests: list[dict] = []
    unparsed: list[str] = []
    if source.is_file():
        files = [source]
    else:
        files = sorted(p for p in source.rglob("*")
                       if p.is_file() and p.suffix.lower() in SCAN_EXT)
        if not files:
            raise ValueError(f"tidak ada file {sorted(SCAN_EXT)} "
                             f"di {source}")
    for f in files:
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                unparsed.append(f"{f}: terlalu besar")
                continue
            docs = parse_documents(f.read_text(encoding="utf-8",
                                               errors="replace"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            unparsed.append(f"{f}: {exc}")
            continue
        found = _extract_manifests(docs)
        if not found:
            unparsed.append(f"{f}: tidak ada objek RBAC dikenali")
            continue
        manifests.extend(found)
    if not manifests:
        raise ValueError("tidak ada manifest RBAC yang dikenali "
                         "(fail-closed — bukti kosong bukan 'bersih')")
    return manifests, unparsed


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="k8s_rbac_audit — audit OFFLINE manifest RBAC "
                    "Kubernetes (read-only, tanpa kubectl/cluster).")
    ap.add_argument("--source", required=True,
                    help="file/dir manifest RBAC (YAML subset atau JSON)")
    ap.add_argument("--fail-on", choices=("critical", "high", "any"),
                    default=None,
                    help="exit 1 bila ada temuan pada level itu")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    source = Path(args.source)
    if not source.exists():
        print(f"[k8s-rbac-audit] source tidak ada: {source}",
              file=sys.stderr)
        return 2
    try:
        manifests, unparsed = _load_files(source)
    except (OSError, ValueError) as exc:
        print(f"[k8s-rbac-audit] gagal: {exc}", file=sys.stderr)
        return 2
    result = audit(manifests)
    result["unparsed"] = unparsed
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    print(f"[k8s-rbac-audit] {result['roles_audited']} role + "
          f"{result['bindings_audited']} binding diaudit "
          f"({result['builtin_system_skipped']} system: dilewati)")
    print(f"[k8s-rbac-audit] temuan: {s['findings_total']} "
          f"({', '.join(f'{k}={v}' for k, v in s['by_severity'].items()) or '-'})")
    for f in result["findings"][:10]:
        print(f"  [{f['severity']:8}] {f['code']:22} {f['where']}")
    for sc in result["escalation_subjects"][:10]:
        print(f"  [eskalasi] {sc['subject']} via {sc['via']} "
              f"({', '.join(sc['escalation'])})")
    if unparsed:
        print(f"[k8s-rbac-audit] unparsed: {len(unparsed)} file "
              "(tercatat, tidak dianggap bersih)")
    if args.fail_on:
        sev = result["summary"]["by_severity"]
        hit = (args.fail_on == "any" and s["findings_total"] > 0) or \
            (args.fail_on == "high" and (sev.get("critical", 0)
                                         + sev.get("high", 0)) > 0) or \
            (args.fail_on == "critical" and sev.get("critical", 0) > 0)
        if hit:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
