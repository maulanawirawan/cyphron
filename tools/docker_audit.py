r"""[SAFETY: read-only] docker_audit — audit OFFLINE konfigurasi Docker
(Dockerfile, daemon.json, docker-compose.yml) terhadap kontrol hardening
kelas CIS Docker Benchmark. TANPA jaringan, TANPA docker daemon.

Port konsep dari antrean SKILL-PORT-QUEUE #0526 + #0527 (mukul975/
Anthropic-Cybersecurity-Skills 'hardening-docker-containers-for-
production', 'hardening-docker-daemon-configuration'; atribusi konsep,
lisensi sumber Apache-2.0). Dibangun FROM SCRATCH: daftar cek ditulis
sendiri dari kontrol hardening publik (non-root, pin digest, tanpa
secret di ENV, daemon icc/live-restore/log, compose privileged).
Skill sumber = runbook live (docker-bench/Hadolint/Dockle + docker
runtime); cyphron memilih audit statis file konfigurasi supaya nol
jaringan dan dapat dites. Ranah: audit konfigurasi SAAT-DEPLOY; audit
runtime image teramati (drift T1611) = ranah deteksi runtime (METHODS
seksi 51), bukan tool ini.

Input -> mekanisme -> output:
  - Input : --dockerfile, --daemon (daemon.json), --compose (yml) —
            minimal satu. Multi-stage Dockerfile dipahami (stage =
            per FROM; USER dinilai pada stage TERAKHIR).
  - Mekanisme: linter baris-basis (Dockerfile/compose, stdlib, tanpa
            PyYAML — pola kunci sederhana) + parser JSON (daemon.json;
            JSON tidak valid = fail-closed exit 2).
  - Output: temuan {check, severity, file, line, message} + notes
            (cek yang butuh daemon hidup dicatat eksplisit).

Cek Dockerfile:
  base-latest-tag     (medium): FROM dgn tag latest / tanpa tag.
  base-not-digest-pin (medium): FROM dgn tag spesifik tapi tanpa @sha256:.
  runs-as-root        (high)  : stage terakhir tanpa USER, atau USER
                                root/0.
  curl-sh-install     (high)  : RUN curl|wget ... | sh/bash (supply
                                chain install-time).
  secret-in-env       (high)  : ENV/ARG bernama password/secret/token/
                                api_key/private_key dgn nilai.
  add-remote          (medium): ADD dari URL (pakai COPY utk file lokal).
  sudo-in-run         (medium): RUN sudo (layer root berantakan).
  healthcheck-missing (low)   : tidak ada HEALTHCHECK.

Cek daemon.json:
  remote-api-plaintext (high) : hosts tcp:// tanpa TLS aktif.
  icc-enabled          (medium): "icc": true eksplisit.
  insecure-registries  (medium): daftar tidak kosong (registry plaintext).
  live-restore-off     (low)  : "live-restore": false eksplisit.
  log-unbounded        (low)  : json-file tanpa max-size.
  no-new-privileges-off(low)  : eksplisit false.
  userland-proxy-on    (low)  : eksplisit true.

Cek compose:
  privileged-service   (high) : privileged: true.
  host-namespace       (medium): network_mode/pid/ipc: host; cap_add
                                SYS_ADMIN.

Fail-closed: file tak terbaca / nol target / daemon.json tidak valid ->
exit 2. Cek yang butuh daemon hidup (audit file unix sock, mode swarm)
dicatat di notes, tidak disimpulkan dari kegelapan.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/docker_audit.py --dockerfile Dockerfile
  python tools/docker_audit.py --daemon daemon.json --fail-on medium
  python tools/docker_audit.py --dockerfile D --daemon d.json --compose c.yml
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "cyphron.docker-audit/1"
MAX_FILE_BYTES = 4 * 1024 * 1024

_SECRET_NAME = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key)", re.I)
_RE_CURL_SH = re.compile(
    r"\b(curl|wget)\b[^|&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I)
_RE_FROM = re.compile(r"^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I)
_RE_USER = re.compile(r"^\s*USER\s+(\S+)\s*$", re.I)
_RE_RUN = re.compile(r"^\s*RUN\s+(.*)$", re.I)
_RE_ENV = re.compile(r"^\s*(ENV|ARG)\s+(.*)$", re.I)
_RE_ADD = re.compile(r"^\s*ADD\s+(\S+)", re.I)
_RE_SUDO = re.compile(r"\bsudo\b")
_RE_HEALTHCHECK = re.compile(r"^\s*HEALTHCHECK\b", re.I)

_COMPOSE_KEYS = ("privileged", "network_mode", "pid", "ipc", "cap_add")


def _read(path: Path) -> "list[str]":
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"tidak terbaca: {path}: {exc}") from exc
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError(f"melebihi batas ukuran: {path}")
    return text.splitlines()


def _unwrap_continuation(lines: "list[str]") -> "list[tuple[int, str]]":
    """Gabung baris Dockerfile dgn backslash-continuation (nomor asli)."""
    out: "list[tuple[int, str]]" = []
    buf = ""
    start = 0
    for i, line in enumerate(lines, 1):
        if buf:
            buf = buf[:-1] + " " + line.strip()
        else:
            start = i
            buf = line
        if buf.rstrip().endswith("\\"):
            continue
        if buf.strip():
            out.append((start, buf))
        buf = ""
    if buf.strip():
        out.append((start, buf))
    return out


# ------------------------------------------------------- Dockerfile
def audit_dockerfile(path: Path) -> "list[dict]":
    lines = _read(path)
    findings: "list[dict]" = []

    def add(check: str, severity: str, lineno: int, msg: str) -> None:
        findings.append({"check": check, "severity": severity,
                         "file": str(path), "line": lineno, "message": msg})

    stages = _unwrap_continuation(lines)
    # Indeks mulai stage terakhir.
    from_idx = [i for i, (_, l) in enumerate(stages)
                if _RE_FROM.match(l)]
    has_healthcheck = any(_RE_HEALTHCHECK.match(l)
                          for _, l in stages)
    if not from_idx:
        add("no-from-found", "medium", 1,
            "Tidak ada instruksi FROM — bukan Dockerfile valid?")
    else:
        last_stage = from_idx[-1]
        final_user = None
        for _, line in stages[last_stage + 1:]:
            m = _RE_USER.match(line)
            if m:
                final_user = m.group(1).lower()
        if final_user in (None, "root", "0"):
            add("runs-as-root", "high", 1,
                "Stage terakhir tidak menetapkan USER non-root "
                "(CIS Docker: buat user khusus) — escape kontainer = "
                "root di host namespace.")
        # Base image stage terakhir (dan semua stage).
        for i, (lineno, line) in enumerate(stages):
            m = _RE_FROM.match(line)
            if not m:
                continue
            base = m.group(1)
            if base.lower() == "scratch":
                continue
            digest = "@sha256:" in base
            tag = base.rsplit(":", 1)[1] if ":" in base else None
            if digest:
                continue
            if tag in (None, "latest"):
                add("base-latest-tag", "medium", lineno,
                    f"FROM '{base}' — tag latest/tanpa tag: build tidak "
                    "reproducible, base bisa berubah diam-diam.")
            else:
                add("base-not-digest-pin", "medium", lineno,
                    f"FROM '{base}' — pin digest @sha256: utk "
                    "reproducibility & integritas base image.")

    for lineno, line in stages:
        m = _RE_RUN.match(line)
        if m and _RE_CURL_SH.search(m.group(1)):
            add("curl-sh-install", "high", lineno,
                "RUN curl|wget piped ke sh — kode pihak ketiga dieksekusi "
                "saat build tanpa verifikasi; pin versi + verifikasi hash.")
        if m and _RE_SUDO.search(m.group(1)):
            add("sudo-in-run", "medium", lineno,
                "RUN sudo — layer dgn hak root terfragmentasi; jalankan "
                "build step sebagai user yang tepat.")
        m = _RE_ENV.match(line)
        if m:
            body = m.group(2)
            for part in body.split():
                name = part.split("=", 1)[0]
                value = part.split("=", 1)[1] if "=" in part else ""
                if _SECRET_NAME.search(name) and value and \
                        not value.startswith("$"):
                    add("secret-in-env", "high", lineno,
                        f"{m.group(1)} {name} berisi nilai literal — "
                        "secret tersimpan di layer/history image; pakai "
                        "secret manager / mount runtime.")
        m = _RE_ADD.match(line)
        if m and re.match(r"^https?://", m.group(1), re.I):
            add("add-remote", "medium", lineno,
                "ADD dari URL — tidak memverifikasi checksum & tidak "
                "bisa di-cache; pakai COPY + verifikasi eksplisit.")

    if not has_healthcheck:
        add("healthcheck-missing", "low", 1,
            "Tidak ada HEALTHCHECK — orkestrator tidak tahu apakah "
            "proses masih sehat.")
    return findings


# ------------------------------------------------------- daemon.json
def audit_daemon(path: Path) -> "list[dict]":
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"tidak terbaca: {path}: {exc}") from exc
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError(f"melebihi batas ukuran: {path}")
    try:
        cfg = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"daemon.json tidak valid: {exc}") from exc
    if not isinstance(cfg, dict):
        raise ValueError("daemon.json bukan objek JSON")
    findings: "list[dict]" = []

    def add(check: str, severity: str, msg: str) -> None:
        findings.append({"check": check, "severity": severity,
                         "file": str(path), "line": None,
                         "message": msg})

    hosts = cfg.get("hosts") or []
    if isinstance(hosts, str):
        hosts = [hosts]
    tcp_hosts = [h for h in hosts if isinstance(h, str)
                 and h.startswith("tcp://")]
    tls_active = bool(cfg.get("tlsverify")) or bool(cfg.get("tls"))
    if tcp_hosts and not tls_active:
        add("remote-api-plaintext", "high",
            f"Daemon listen {tcp_hosts} tanpa TLS — API Docker remote "
            "plaintext = RCE jarak jauh bagi siapa pun yang menembus "
            "jaringan; pakai tlsverify + CA.")
    if cfg.get("icc") is True:
        add("icc-enabled", "medium",
            "icc: true — semua kontainer saling menembus tanpa filter "
            "(CIS: icc=false + kebijakan antar-kontainer eksplisit).")
    ins_reg = cfg.get("insecure-registries") or []
    if ins_reg:
        add("insecure-registries", "medium",
            f"insecure-registries {ins_reg} — image ditarik via "
            "plaintext/terverifikasi-samar (MITM bisa menukar image).")
    if cfg.get("live-restore") is False:
        add("live-restore-off", "low",
            "live-restore: false — daemon restart mematikan kontainer "
            "jalan (resiliensi operasional).")
    if cfg.get("no-new-privileges") is False:
        add("no-new-privileges-off", "low",
            "no-new-privileges: false — setuid/cap baru diperbolehkan "
            "di dalam kontainer.")
    if cfg.get("userland-proxy") is True:
        add("userland-proxy-on", "low",
            "userland-proxy: true — docker-proxy userland aktif di depan "
            "publikasi port (luas permukaan, ciculan NAT).")
    log_driver = cfg.get("log-driver", "json-file")
    log_opts = cfg.get("log-opts") or {}
    if log_driver == "json-file" and "max-size" not in log_opts:
        add("log-unbounded", "low",
            "log-driver json-file tanpa max-size — log kontainer "
            "bertumbuh tanpa batas (disk DoS).")
    return findings


# ------------------------------------------------------- compose
def audit_compose(path: Path) -> "list[dict]":
    lines = _read(path)
    findings: "list[dict]" = []

    def add(check: str, severity: str, lineno: int, msg: str) -> None:
        findings.append({"check": check, "severity": severity,
                         "file": str(path), "line": lineno,
                         "message": msg})

    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if line.startswith("#"):
            continue
        m = re.match(r"^privileged:\s*true\b", line, re.I)
        if m:
            add("privileged-service", "high", i,
                "privileged: true — kontainer hampir tanpa isolasi "
                "(akses device host); batasi capability yang dibutuhkan.")
        m = re.match(r"^(network_mode|pid|ipc):\s*host\b", line, re.I)
        if m:
            add("host-namespace", "medium", i,
                f"'{m.group(1)}: host' — kontainer berbagi namespace "
                "host (jaringan/proses/IPC terlihat dan bisa "
                "dimanipulasi).")
        if re.match(r"^cap_add:", line, re.I):
            if re.search(r"\bSYS_ADMIN\b", line):
                add("host-namespace", "medium", i,
                    "cap_add SYS_ADMIN — hampir setara privileged; "
                    "tinjau capability minimal.")
    return findings


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit konfigurasi Docker (Dockerfile/daemon.json/"
                    "compose) offline, nol jaringan.")
    ap.add_argument("--dockerfile", default=None)
    ap.add_argument("--daemon", default=None)
    ap.add_argument("--compose", default=None)
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high"],
                    help="severity minimum yang memicu exit 1 (default high)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    if not (args.dockerfile or args.daemon or args.compose):
        ap.error("butuh minimal satu: --dockerfile / --daemon / --compose")

    findings: "list[dict]" = []
    try:
        if args.dockerfile:
            findings += audit_dockerfile(Path(args.dockerfile))
        if args.daemon:
            findings += audit_daemon(Path(args.daemon))
        if args.compose:
            findings += audit_compose(Path(args.compose))
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    threshold = SEVERITY_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    notes = [
        "audit statis file konfigurasi — kepatuhan runtime (drift, "
        "package manager di kontainer jalan, akses docker.sock) butuh "
        "telemetri daemon/EDR, tidak dinilai dari file.",
        "severities mengikuti kontrol hardening kelas CIS Docker; "
        "konteks lingkungan (dev vs produksi) menentukan prioritas "
        "remediasi.",
    ]
    report = {
        "schema": SCHEMA,
        "findings": sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0),
                           f["file"], f.get("line") or 0, f["check"])),
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
