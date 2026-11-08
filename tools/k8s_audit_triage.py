"""[SAFETY: read-only] k8s_audit_triage — triase OFFLINE audit log
kube-apiserver (JSONL) utk jejak penyalahgunaan API Kubernetes.

Port konsep dari antrean SKILL-PORT-QUEUE #0205 (mukul975/
Anthropic-Cybersecurity-Skills 'analyzing-kubernetes-audit-logs' —
deteksi exec-into-pod, akses secrets, modifikasi RBAC, pod
privileged, akses anonymous dari audit log JSONL; lisensi skill
sumber Apache-2.0, atribusi konsep — kode ini ditulis from scratch,
stdlib-only, NOL jaringan: input = file audit log hasil ekspor
lab/berizin, TIDAK menghubungi cluster apapun).

Mekanisme (semua temuan = LEAD teramati di log, agregat per
pengguna, sampel disertakan):
  - pod-exec        : create pods dengan subresource exec/attach/
                      portforward (resource 'pods/exec' gaya ringkas
                      juga dinormalisasi)
  - secret-access   : get (medium) / list-watch (high) resource
                      secrets oleh satu pengguna
  - rbac-escalation : create/update clusterrolebinding = critical;
                      mutasi roles/rolebindings/clusterroles = high
  - privileged-pod  : create pods dengan container privileged,
                      hostPID/hostNetwork/hostIPC, atau volume
                      hostPath (butuh requestObject tercatat —
                      cakupan dilaporkan di meta, tidak diasumsikan)
  - anonymous-access: user system:anonymous / grup
                      system:unauthenticated
  - impersonation   : event dengan impersonatedUser (header
                      Impersonate)

Dedup: satu auditID bisa tercatat di beberapa stage — event
di-dedupe (ResponseComplete diprioritaskan); duplikat dihitung di
meta.duplicate_audits. Response 403 dihitung di meta.denied_events
(tak diflag sebagai temuan — permintaan itu DITOLAK).

Fail-closed: file kosong / nol baris JSON audit valid -> exit 2;
baris bukan-JSON / tanpa 'verb' dihitung + disampel, tidak dibuang.
--fail-on critical|high|any utk gate.

Pemakaian:
  python tools/k8s_audit_triage.py --log audit.log --out t.json
  python tools/k8s_audit_triage.py --log audit.log --fail-on critical
Exit: 0 sukses; 1 gate --fail-on kena; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "secai.k8s-audit-triage/1"

_UNPARSED_SAMPLE_MAX = 20
_SAMPLE_MAX = 10

_MUTATE_VERBS = {"create", "update", "patch", "delete",
                 "deletecollection", "bind", "escalate"}
_RBAC_RESOURCES = {"roles", "rolebindings", "clusterroles",
                   "clusterrolebindings"}


def _normalize_ref(event: dict) -> tuple[str, str]:
    """(resource, subresource) — mendukung gaya 'pods/exec'."""
    ref = event.get("objectRef") or {}
    resource = str(ref.get("resource") or "")
    sub = str(ref.get("subresource") or "")
    if "/" in resource:
        resource, _, sub = resource.partition("/")
    return resource, sub


def _dedupe_events(rows: list[dict]) -> tuple[list[dict], int]:
    """Dedupe by auditID; preferensi baris dengan responseStatus."""
    seen: dict[str, dict] = {}
    dup = 0
    no_id = 0
    for row in rows:
        audit_id = row.get("auditID")
        if not audit_id:
            no_id += 1
            seen[f"__noid_{no_id}"] = row
            continue
        if audit_id not in seen:
            seen[audit_id] = row
            continue
        dup += 1
        cur = seen[audit_id]
        if not cur.get("responseStatus") and row.get("responseStatus"):
            seen[audit_id] = row
    return list(seen.values()), dup


def _pod_privilege_reasons(obj: dict) -> list[str]:
    """Alasan flag dari requestObject pod — deterministik."""
    reasons: list[str] = []
    if not isinstance(obj, dict):
        return reasons
    spec = obj.get("spec") or {}
    if not isinstance(spec, dict):
        return reasons
    for key in ("hostPID", "hostNetwork", "hostIPC"):
        if spec.get(key) is True:
            reasons.append(key)
    for cname in ("containers", "initContainers", "ephemeralContainers"):
        for c in spec.get(cname) or []:
            if not isinstance(c, dict):
                continue
            sc = c.get("securityContext") or {}
            if sc.get("privileged") is True:
                reasons.append(f"privileged:{c.get('name', '?')}")
            if sc.get("procMount") not in (None, "Default"):
                reasons.append(f"procMount:{c.get('name', '?')}")
    for vol in spec.get("volumes") or []:
        if isinstance(vol, dict) and "hostPath" in vol:
            path = (vol.get("hostPath") or {}).get("path", "?")
            reasons.append(f"hostPath:{path}")
    return reasons


def analyze(events: list[dict]) -> tuple[list[dict], dict]:
    """Klasifikasi event -> temuan agregat per (user, type)."""
    groups: dict[tuple[str, str], list[dict]] = {}
    priv_reasons: dict[tuple[str, str], dict[str, list[str]]] = {}
    verb_hist: Counter = Counter()
    denied = 0
    ro_coverage = 0

    for ev in events:
        user = str((ev.get("user") or {}).get("username") or "?")
        verb = str(ev.get("verb") or "?")
        resource, sub = _normalize_ref(ev)
        verb_hist[verb] += 1
        status = ev.get("responseStatus") or {}
        if isinstance(status, dict) and status.get("code") == 403:
            denied += 1
        # anonim
        ugroups = [str(g) for g in (ev.get("user") or {}).get(
            "groups") or []]
        if user == "system:anonymous" or ("system:unauthenticated"
                                          in ugroups):
            groups.setdefault((user, "anonymous-access"),
                              []).append(ev)
        if (ev.get("impersonatedUser") or {}).get("username"):
            groups.setdefault((user, "impersonation"),
                              []).append(ev)
        # pod exec/attach/portforward
        if resource == "pods" and sub in ("exec", "attach",
                                          "portforward"):
            groups.setdefault((user, "pod-exec"), []).append(ev)
        # secrets
        if resource == "secrets" and verb in ("get", "list", "watch"):
            bulk = verb in ("list", "watch")
            key = "secret-access-bulk" if bulk else "secret-access-get"
            groups.setdefault((user, key), []).append(ev)
        # rbac
        if resource in _RBAC_RESOURCES and verb in _MUTATE_VERBS:
            key = ("rbac-clusterrolebinding" if resource ==
                   "clusterrolebindings" else "rbac-mutation")
            groups.setdefault((user, key), []).append(ev)
        # privileged pod
        if resource == "pods" and verb == "create":
            ro = ev.get("requestObject")
            if ro is not None:
                ro_coverage += 1
                reasons = _pod_privilege_reasons(ro if isinstance(
                    ro, dict) else {})
                if reasons:
                    priv_reasons.setdefault((user, "privileged-pod"),
                                            {})[str(
                        (ev.get("objectRef") or {}).get("name")
                        or "?")] = reasons

    meta = {
        "verb_histogram": verb_hist.most_common(10),
        "denied_events": denied,
        "requestobject_coverage": ro_coverage,
    }

    findings: list[dict] = []

    def add(ftype: str, sev: str, user: str, evs: list[dict],
            detail: str, extra: dict | None = None) -> None:
        samples = []
        for ev in evs[:_SAMPLE_MAX]:
            ref = ev.get("objectRef") or {}
            samples.append({
                "verb": ev.get("verb"),
                "resource": ref.get("resource"),
                "subresource": ref.get("subresource"),
                "name": ref.get("name"),
                "namespace": ref.get("namespace"),
                "sourceIPs": (ev.get("sourceIPs") or [])[:4],
            })
        evidence: dict = {"events": len(evs), "samples": samples}
        if extra:
            evidence.update(extra)
        findings.append({
            "type": ftype, "severity": sev, "user": user,
            "detail": detail, "evidence": evidence,
        })

    for (user, ftype), evs in sorted(groups.items()):
        if not evs:
            continue
        if ftype == "pod-exec":
            subs = sorted({(e.get("objectRef") or {}).get(
                "subresource") or "?" for e in evs})
            add("pod-exec", "high", user, evs,
                f"{len(evs)} akses exec/attach ke pod")
            findings[-1]["evidence"]["subresources"] = subs
        elif ftype == "secret-access-bulk":
            add("secret-access", "high", user, evs,
                f"{len(evs)} kueri list/watch secrets (akses massal)")
        elif ftype == "secret-access-get":
            add("secret-access", "medium", user, evs,
                f"{len(evs)} kueri get secrets")
        elif ftype == "rbac-clusterrolebinding":
            add("rbac-escalation", "critical", user, evs,
                f"{len(evs)} mutasi clusterrolebinding (eskalasi "
                "klaster penuh)")
        elif ftype == "rbac-mutation":
            add("rbac-escalation", "high", user, evs,
                f"{len(evs)} mutasi objek RBAC")
        elif ftype == "anonymous-access":
            add("anonymous-access", "high", user, evs,
                f"{len(evs)} akses anonymous/unauthenticated")
        elif ftype == "impersonation":
            add("impersonation", "high", user, evs,
                f"{len(evs)} event dengan impersonatedUser")

    for (user, ftype), pods in sorted(priv_reasons.items()):
        total = sum(len(v) for v in pods.values())
        findings.append({
            "type": ftype, "severity": "high", "user": user,
            "detail": f"{total} alasan privilege pada pod yang "
                      "dibuat",
            "evidence": {"pods": dict(list(pods.items())
                                      [:_SAMPLE_MAX])},
        })

    order = {"critical": 0, "high": 1, "medium": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings, meta


def triage_file(path: Path, fail_on: str | None = None) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise ValueError("file kosong")
    rows: list[dict] = []
    unparsed: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            unparsed.append(line[:200])
            continue
        if not isinstance(obj, dict) or "verb" not in obj:
            unparsed.append(line[:200])
            continue
        rows.append(obj)
    if not rows:
        raise ValueError("tidak ada baris audit JSON yang valid")

    events, dup = _dedupe_events(rows)
    findings, meta = analyze(events)

    users = Counter(str((e.get("user") or {}).get("username") or "?")
                    for e in events)

    out: dict = {
        "schema": SCHEMA,
        "file": str(path),
        "lines_total": len(text.splitlines()),
        "parsed": len(rows),
        "unparsed_count": len(unparsed),
        "unparsed_sample": unparsed[:_UNPARSED_SAMPLE_MAX],
        "events": len(events),
        "duplicate_audits": dup,
        "users": len(users),
        "user_top": users.most_common(10),
        "finding_count": len(findings),
        "findings": findings,
        "meta": meta,
        "note": "semua temuan = LEAD teramati di audit log, bukan "
                "klaim kompromi terkonfirmasi",
        "read_only": True,
    }
    if fail_on:
        rank = {"critical": 0, "high": 1, "medium": 2}
        thresh = 0 if fail_on == "critical" else (
            1 if fail_on == "high" else 2 if fail_on == "any" else None)
        if thresh is None:
            raise ValueError("--fail-on harus critical|high|any")
        hit = [f for f in findings
               if f["severity"] in rank
               and rank[f["severity"]] <= thresh]
        out["fail_on"] = fail_on
        out["fail_on_hit"] = len(hit)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase audit log kube-apiserver (JSONL) utk "
                    "exec/secrets/RBAC/privileged/anonymous "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--log", required=True,
                    help="file audit log JSONL kube-apiserver")
    ap.add_argument("--fail-on", choices=["critical", "high", "any"],
                    help="exit 1 bila ada temuan pada level ini")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.log)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage_file(path, args.fail_on)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    rc = 1 if (args.fail_on and result.get("fail_on_hit")) else 0
    if rc:
        print(f"fail-on {args.fail_on}: "
              f"{result['fail_on_hit']} temuan", file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
