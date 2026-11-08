r"""[AUDIT: read-only] k8s_podsec_audit — audit OFFLINE spesifikasi pod
Kubernetes terhadap Pod Security Standards (Baseline / Restricted):
linter manifest statis yang menjawab "workload mana yang GAGAL level X"
sebelum apply / dari repo GitOps.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/implementing-kubernetes-pod-security-standards' (#0653 —
pemilihan profil PSS, pemetaan securityContext, dry-run enforcement;
atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM SCRATCH
TANPA kode sumber itu: aturan cek ditulis dari spesifikasi publik PSS
(kubernetes.io/docs/concepts/security/pod-security-standards). Skill
sumber = runbook kubectl/cluster (label namespace, dry-run PSA); tool
ini memilih sisi statis: TIDAK menjalankan kubectl dan TIDAK menyentuh
cluster. Ranah tool tetangga ditulis eksplisit: manifest RBAC =
k8s_rbac_audit (B09), audit log API server (pod-exec/secret-access/
privileged saat JALAN) = k8s_audit_triage (B07); tool ini = spesifik
definisi pod SAAT-DEPLOY vs profil PSS.

Input -> mekanisme -> output:
  - Input   : --source FILE/DIR (YAML subset atau JSON, pola loader
              k8s_rbac_audit.parse_documents) + --profile
              restricted (default) | baseline.
  - Mekanisme: ekstrak pod spec dari workload (Pod, Deployment,
              StatefulSet, DaemonSet, ReplicaSet, Job -> .spec.template
              .spec; CronJob -> .spec.jobTemplate.spec.template.spec;
              List.items direkursi) lalu cek deterministik per
              container + pod-level.
  - Output  : temuan {check, severity, workload, container, field,
              message} + summary + notes.

Cek (level minimum tempat cek itu berlaku — semua cek BASELINE juga
pelanggaran RESTRICTED):
  privileged            (high)   : container .privileged=true
  host-pid/ipc          (high)   : pod hostPID/hostIPC=true
  host-network          (medium) : pod hostNetwork=true
  host-path-volume      (high)   : volume hostPath
  host-port             (medium) : containerPort hostPort diset
  disallowed-cap-add    (high)   : cap di luar daftar allowlist
                                   Baseline (SYS_ADMIN, NET_ADMIN, dst)
  proc-mount            (medium) : procMount != Default
  unsafe-sysctl         (medium) : sysctl di luar daftar aman Baseline
  selinux-custom-type   (medium) : seLinuxOptions.type diset (custom)
  apparmor-unconfined   (low)    : AppArmor unconfined eksplisit
  volume-type           (medium) : [RESTRICTED] tipe volume di luar
                                   allowlist (configMap, csi, secret,
                                   dst.)
  allow-priv-esc        (high)   : [RESTRICTED] allowPrivilegeEscalation
                                   true atau TIDAK diset eksplisit
  cap-drop-all-missing  (high)   : [RESTRICTED] capabilities.drop
                                   tidak memuat ALL
  restricted-cap-add    (high)   : [RESTRICTED] add selain
                                   NET_BIND_SERVICE
  run-as-non-root       (high/   : [RESTRICTED] runAsNonRoot false
                          medium)  (high) atau tidak diset di level
                                   pod maupun container (medium)
  run-as-user-root      (high)   : [RESTRICTED] runAsUser: 0
  seccomp-profile       (high/   : [RESTRICTED] seccompProfile.type
                          medium)  Unconfined (high) atau tidak diset
                                   di level pod maupun container (medium)

Fail-closed: source tidak ada / tidak ada workload dikenali -> exit 2;
file tidak ter-parse tercatat di unparsed dan TIDAK diam-diam dianggap
bersih. Enforce/audit/warn namespace PSA (label) dan pengecualian
exempt namespace = pemeriksaan live-cluster, dicatat di notes.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from k8s_rbac_audit import parse_documents  # noqa: E402

SCHEMA = "cyphron.k8s-podsec-audit/1"
MAX_FILE_BYTES = 4 * 1024 * 1024
SCAN_EXT = {".yaml", ".yml", ".json"}

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet",
                  "ReplicaSet", "Job", "CronJob"}

# capabilities yang MASIH BOLEH di-add pada level Baseline (daftar PSS).
BASELINE_CAP_ADD = {
    "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
    "MKNOD", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID",
    "SETPCAP", "SETUID", "SYS_CHROOT",
}
# satu-satunya cap yang boleh di-add pada level Restricted.
RESTRICTED_CAP_ADD = {"NET_BIND_SERVICE"}
# tipe volume yang diizinkan Restricted.
RESTRICTED_VOLUME_TYPES = {
    "configMap", "csi", "downwardAPI", "emptyDir", "ephemeral",
    "persistentVolumeClaim", "projected", "secret",
}
# sysctl yang dianggap aman oleh Baseline.
SAFE_SYSCTLS = {
    "kernel.shm_rmid_forced",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.ip_unprivileged_port_start",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _bool_or_none(v: object) -> "bool | None":
    """Normalisasi boolean: parser YAML subset mengembalikan skalar
    string ('true'), JSON mengembalikan bool. Tri-state bila tak
    diset / tak dikenal."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        low = v.strip().lower()
        if low == "true":
            return True
        if low == "false":
            return False
    return None


def _num(v: object) -> "int | None":
    """Angka dari skalar bool/string/int (hostPort, runAsUser)."""
    try:
        return int(str(v).strip().strip("'\""))
    except (TypeError, ValueError):
        return None


def _load_workloads(source: Path) -> "tuple[list[dict], list[str]]":
    """Muat manifest dari file/dir dan ekstrak pod spec per workload."""
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

    workloads: "list[dict]" = []

    def kind_name(d: dict) -> str:
        return f"{d.get('kind', '?')}/{d.get('metadata', {}).get('name', '?')}"

    def visit(d: dict) -> None:
        if not isinstance(d, dict):
            return
        kind = d.get("kind")
        if kind == "List" and isinstance(d.get("items"), list):
            for item in d["items"]:
                visit(item)
            return
        if kind not in WORKLOAD_KINDS:
            return
        spec = _pod_spec(d)
        if spec is None:
            unparsed.append(f"{kind_name(d)}: pod spec tidak ditemukan")
            return
        workloads.append({"ref": kind_name(d), "spec": spec})

    for d in docs:
        if isinstance(d, dict):
            visit(d)

    if not workloads:
        raise ValueError("tidak ada workload pod yang dikenali "
                         "(fail-closed — bukti kosong bukan 'bersih')")
    return workloads, unparsed


def _pod_spec(d: dict) -> "dict | None":
    """Ambil pod spec sesuai kind; None bila struktur tak dikenal."""
    spec = d.get("spec")
    if not isinstance(spec, dict):
        return None
    kind = d.get("kind")
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job = spec.get("jobTemplate")
        tpl = (job or {}).get("spec", {}).get("template", {}) \
            if isinstance(job, dict) else {}
        ps = tpl.get("spec")
        return ps if isinstance(ps, dict) else None
    # Deployment/StatefulSet/DaemonSet/ReplicaSet/Job
    tpl = spec.get("template", {})
    ps = tpl.get("spec") if isinstance(tpl, dict) else None
    return ps if isinstance(ps, dict) else None


def audit_workload(ref: str, spec: dict, profile: str) -> "list[dict]":
    findings: "list[dict]" = []

    def add(check: str, severity: str, container: str | None,
            field: str, msg: str) -> None:
        findings.append({"check": check, "severity": severity,
                         "workload": ref, "container": container,
                         "field": field, "message": msg})

    restricted = (profile == "restricted")

    # ---- pod level (Baseline)
    host_pid = _bool_or_none(spec.get("hostPID"))
    host_ipc = _bool_or_none(spec.get("hostIPC"))
    if host_pid is True or host_ipc is True:
        which = "+".join(w for w, v in (("hostPID", host_pid),
                                        ("hostIPC", host_ipc))
                         if v is True)
        add("host-pid/ipc", "high", None, which,
            f"{which}=true — pod berbagi namespace proses/IPC host "
            "(Baseline melarang; melihat dan membunuh proses host).")
    if _bool_or_none(spec.get("hostNetwork")) is True:
        add("host-network", "medium", None, "hostNetwork",
            "hostNetwork=true — pod memakai stack jaringan host "
            "(melewati NetworkPolicy; port host langsung).")

    volumes = spec.get("volumes") or []
    for v in volumes:
        if not isinstance(v, dict):
            continue
        if "hostPath" in v:
            add("host-path-volume", "high", None,
                f"volumes[{v.get('name', '?')}]",
                "volume hostPath — akses filesystem host dari pod "
                "(Baseline melarang; jalur escape klasik).")
        elif restricted:
            vtypes = set(v) - {"name"}
            if vtypes and not (vtypes & RESTRICTED_VOLUME_TYPES):
                add("volume-type", "medium", None,
                    f"volumes[{v.get('name', '?')}]",
                    f"tipe volume {sorted(vtypes)} tidak diizinkan "
                    "Restricted (hanya configMap/csi/downwardAPI/"
                    "emptyDir/ephemeral/pvc/projected/secret).")

    sysctls = spec.get("securityContext", {}).get("sysctls") or []
    for sc in sysctls:
        if isinstance(sc, dict) and sc.get("name") not in SAFE_SYSCTLS:
            add("unsafe-sysctl", "medium", None,
                f"sysctl[{sc.get('name', '?')}]",
                "sysctl di luar daftar aman Baseline — bisa memengaruhi "
                "kernel host / jaringan node.")

    pod_non_root = _bool_or_none(
        (spec.get("securityContext") or {}).get("runAsNonRoot"))
    pod_seccomp = (spec.get("securityContext") or {}) \
        .get("seccompProfile", {})
    if not isinstance(pod_seccomp, dict):
        pod_seccomp = {}

    containers = list(spec.get("containers") or [])
    containers += list(spec.get("initContainers") or [])
    containers += list(spec.get("ephemeralContainers") or [])
    if not containers:
        add("no-containers", "medium", None, "containers",
            "pod spec tanpa container yang bisa dinilai — struktur "
            "tidak lazim, periksa manual.")
    for c in containers:
        if not isinstance(c, dict):
            continue
        cname = c.get("name", "?")
        sc = c.get("securityContext") or {}
        if not isinstance(sc, dict):
            sc = {}

        # ---- Baseline checks
        if _bool_or_none(sc.get("privileged")) is True:
            add("privileged", "high", cname, "securityContext.privileged",
                "privileged=true — kontainer hampir tanpa isolasi "
                "(semua device host, disable seccomp).")
        for port in c.get("ports") or []:
            if isinstance(port, dict) and _num(port.get("hostPort")):
                add("host-port", "medium", cname, "hostPort",
                    f"hostPort={port.get('hostPort')} — mengikat port "
                    "host; jadwal pod jadi terbatas node tertentu.")
        caps = (sc.get("capabilities") or {}) if isinstance(
            sc.get("capabilities"), dict) else {}
        for cap in caps.get("add") or []:
            cap_u = str(cap).upper().removeprefix("CAP_")
            if cap_u not in BASELINE_CAP_ADD:
                add("disallowed-cap-add", "high", cname,
                    f"capabilities.add[{cap_u}]",
                    f"{cap_u} di luar allowlist Baseline — capability "
                    "linux berisiko; kurangi ke yang benar-benar "
                    "dibutuhkan.")
        if (sc.get("procMount") or "Default") != "Default":
            add("proc-mount", "medium", cname, "procMount",
                f"procMount={sc.get('procMount')} — mengekspos /proc "
                "mentah (Baseline hanya Default).")
        sel = (sc.get("seLinuxOptions") or {}) if isinstance(
            sc.get("seLinuxOptions"), dict) else {}
        if sel.get("type"):
            add("selinux-custom-type", "medium", cname,
                f"seLinuxOptions.type[{sel['type']}]",
                "SELinux type kustom — Baseline hanya mengizinkan tipe "
                "default (S0/SPC_t per versi PSS).")
        aa = sc.get("appArmorProfile") or {}
        if isinstance(aa, dict) and aa.get("type") == "Unconfined":
            add("apparmor-unconfined", "low", cname, "appArmorProfile",
                "AppArmor Unconfined eksplisit — tanpa profil "
                "pembatasan (Restricted melarang).")

        # ---- Restricted-only checks
        if restricted:
            ape = _bool_or_none(sc.get("allowPrivilegeEscalation"))
            if ape is True:
                add("allow-priv-esc", "high", cname,
                    "allowPrivilegeEscalation",
                    "allowPrivilegeEscalation=true — setuid/cap baru "
                    "diizinkan; Restricted mewajibkan false eksplisit.")
            elif ape is None:
                add("allow-priv-esc", "high", cname,
                    "allowPrivilegeEscalation",
                    "allowPrivilegeEscalation TIDAK diset — Restricted "
                    "menuntut false eksplisit (default runtime bisa "
                    "true).")
            drop = {str(d).upper().removeprefix("CAP_")
                    for d in caps.get("drop") or []}
            if "ALL" not in drop:
                add("cap-drop-all-missing", "high", cname,
                    "capabilities.drop",
                    "capabilities.drop tidak memuat ALL — Restricted "
                    "menuntut drop ALL lalu add selektif.")
            for cap in caps.get("add") or []:
                cap_u = str(cap).upper().removeprefix("CAP_")
                if cap_u not in RESTRICTED_CAP_ADD:
                    add("restricted-cap-add", "high", cname,
                        f"capabilities.add[{cap_u}]",
                        f"add {cap_u} — Restricted hanya membolehkan "
                        "NET_BIND_SERVICE.")
            ranr = _bool_or_none(
                sc["runAsNonRoot"]) if "runAsNonRoot" in sc else pod_non_root
            if ranr is False:
                add("run-as-non-root", "high", cname, "runAsNonRoot",
                    "runAsNonRoot=false — kontainer boleh jalan sebagai "
                    "root (Restricted melarang).")
            elif ranr is None:
                add("run-as-non-root", "medium", cname, "runAsNonRoot",
                    "runAsNonRoot tidak diset di container maupun "
                    "pod-level — Restricted menuntut true eksplisit "
                    "(pengakuan user root tak terbendung).")
            pod_run_user = _num((spec.get("securityContext") or {})
                                .get("runAsUser")) \
                if "runAsUser" not in sc else None
            effective_uid = _num(sc["runAsUser"]) if "runAsUser" in sc \
                else pod_run_user
            if effective_uid == 0:
                add("run-as-user-root", "high", cname, "runAsUser",
                    "runAsUser=0 — UID root eksplisit (Restricted "
                    "melarang).")
            scc = sc.get("seccompProfile")
            scc = scc if isinstance(scc, dict) else pod_seccomp
            stype = scc.get("type")
            if stype == "Unconfined":
                add("seccomp-profile", "high", cname, "seccompProfile",
                    "seccompProfile.type=Unconfined — tanpa filter "
                    "syscall (Restricted melarang).")
            elif stype is None:
                add("seccomp-profile", "medium", cname, "seccompProfile",
                    "seccompProfile tidak diset di container maupun "
                    "pod-level — Restricted menuntut RuntimeDefault/"
                    "Localhost.")
            elif stype not in ("RuntimeDefault", "Localhost"):
                add("seccomp-profile", "high", cname, "seccompProfile",
                    f"seccompProfile.type={stype} tidak dikenal — "
                    "hanya RuntimeDefault/Localhost yang sah.")
    return findings


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit offline spec pod Kubernetes vs Pod Security "
                    "Standards (Baseline/Restricted), nol jaringan.")
    ap.add_argument("--source", required=True,
                    help="file atau direktori manifest (YAML subset/JSON)")
    ap.add_argument("--profile", default="restricted",
                    choices=["baseline", "restricted"],
                    help="profil PSS yang dijadikan target (default "
                         "restricted — jawab 'apa saja yang gagal "
                         "Restricted')")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    try:
        workloads, unparsed = _load_workloads(Path(args.source))
    except (ValueError, OSError) as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    findings: "list[dict]" = []
    for w in workloads:
        findings += audit_workload(w["ref"], w["spec"], args.profile)

    threshold = SEVERITY_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    summary = {
        "profile": args.profile,
        "workloads_audited": len(workloads),
        "findings": len(findings),
        "by_severity": {
            s: sum(1 for f in findings if f["severity"] == s)
            for s in ("high", "medium", "low")
        },
        "unparsed": unparsed,
    }
    notes = [
        "audit statis spesifik definisi pod — label PSA namespace "
        "(enforce/audit/warn), pengecualian exempt, dan pelanggaran "
        "SAAT JALAN (drift, exec) = pemeriksaan cluster; sisi log "
        "jalan dilayani k8s_audit_triage, sisi RBAC k8s_rbac_audit.",
        "cek mengikuti spesifikasi publik Pod Security Standards; "
        "temuan 'TIDAK diset' pada Restricted bersifat deterministik "
        "terhadap profil (bukan menduga perilaku runtime).",
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
                           f["workload"], f["container"] or "",
                           f["check"])),
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
