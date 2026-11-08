r"""[AUDIT: read-only] linux_cis_audit — audit OFFLINE berkas konfigurasi
Linux terkumpul (sshd_config, sysctl, pwquality.conf, login.defs) terhadap
cek turunan CIS Benchmark (kelas sumber #0528).

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/hardening-linux-endpoint-with-cis-benchmark' (#0528 — atribusi
konsep, lisensi sumber Apache-2.0). Dibangun FROM SCRATCH TANPA kode
sumber itu: ambang & nilai acuan diambil dari langkah konfigurasi yang
tertulis di skill sumber (Section 3 jaringan/sysctl, Section 5.2-5.4
SSH/pwquality/login.defs) dan semantik publik masing-masing berkas
(man sshd_config, man sysctl.d, man pwquality.conf, man login.defs).
Skill sumber = runbook LIVE (menembak `sed -i`/`systemctl` di host);
tool ini memilih sisi STATIS: mengaudit EKSPOR/BERKAS YANG DIKUMPUL
tanpa menyentuh host — pola yang sama dengan docker_audit (#0526).

Ranah tetangga eksplisit: integritas file = aide_change_triage (#0626),
integritas log = log_chain_verify (#0656), audit Docker = docker_audit,
audit Kubernetes = k8s_podsec_audit/netpol_audit/psa_ns_audit, audit
AWS/GCP = aws_config_audit/gcp_*. Tool ini TIDAK menjalankan SSH,
TIDAK membaca host jauh.

Input -> mekanisme -> output:
  - Input   : --sshd FILE... (sshd_config), --sysctl FILE...
              (sysctl.conf / gabungan /etc/sysctl.d atau dump
              `sysctl -a`), --pwquality FILE... , --login-defs FILE...
              (minimal satu kelompok; boleh berulang / beberapa file).
  - Mekanisme: parser baris-basis per format; komentar dilewati;
              sshd = nilai PERTAMA yang menang (semantik OpenSSH),
              sysctl = nilai TERAKHIR yang menang (semantik sysctl.d),
              pwquality/login.defs = nilai terakhir; nilai salah /
              parameter absen = temuan (absen TIDAK dianggap aman —
              fail-closed, message menyebut default).
  - Output  : temuan {check, severity, object, field, message} +
              summary + notes; exit 1 bila temuan >= --fail-on
              (default medium), exit 2 bila file tidak terbaca atau
              tak ada kelompok file yang diberikan.

Cek sshd (acuan nilai = skill sumber 5.2):
  sshd-permitrootlogin           (high 'yes'/medium absen atau prohibit-password)
  sshd-passwordauthentication    (high 'yes'/medium absen)
  sshd-permitemptypasswords      (high selain 'no'/medium absen)
  sshd-maxauthtries              (medium absen atau > 4)
  sshd-login-gracetime           (medium absen atau > 60 detik)
  sshd-maxstartups               (medium ambang awal > 10/low absen)
  sshd-x11forwarding             (medium 'yes'/low absen)
  sshd-tcpforwarding             (medium 'yes'/low absen)
  sshd-loglevel                  (low selain VERBOSE)
  sshd-clientaliveinterval       (low interval 0/low absen)

Cek sysctl (acuan = skill sumber 3.1, host bukan router):
  sysctl-param           (medium per parameter salah/absen; IP forward,
                          send_redirects, accept_source_route,
                          accept_redirects, secure_redirects, rp_filter,
                          tcp_syncookies, log_martians, icmp echo/bogus,
                          ipv6 accept_ra)

Cek pwquality (acuan = skill sumber 5.3):
  pwq-minlen             (medium absen atau < 14)
  pwq-class-credit       (low per d/u/o/l credit yang absen/bukan -1)

Cek login.defs (acuan = skill sumber 5.4):
  ldefs-pass-max-days    (medium absen atau > 365)
  ldefs-pass-min-days    (low absen atau 0)
  ldefs-pass-warn-age    (low absen atau < 7)
  ldefs-encrypt-method   (medium MD5/DES/low absen)

Anti-FP: --allow-check NAME (boleh diulang), jumlah saringan dicatat.
Stdlib re/argparse/json. Nol jaringan.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "linux_cis_audit/v1"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

# ---------------------------------------------------------------- parser

def _read_kv(text: str, sep: str) -> "list[tuple[str, str, bool]]":
    """(kunci, nilai, terkomentar) per baris efektif; komentar # dilewati
    sebagai entri terkomentar (untuk catatan default)."""
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        commented = line.startswith("#")
        if commented:
            line = line.lstrip("#").strip()
        if not line or line.startswith("["):
            continue
        if sep == "space":
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts
        else:
            if sep not in line:
                continue
            key, _, val = line.partition(sep)
            key, val = key.strip(), val.strip()
        rows.append((key, val, commented))
    return rows


def _first_win(rows, key):
    for k, v, commented in rows:
        if commented:
            continue  # direktif terkomentar = tidak aktif (absen)
        if k.lower() == key.lower():
            return v, commented
    return None, None


def _last_win(rows, key):
    found = None
    for k, v, commented in rows:
        if commented:
            continue
        if k.lower() == key.lower():
            found = (v, commented)
    return found or (None, None)


def _normalize_sysctl_key(key: str) -> str:
    return key.replace("/", ".").strip().lower()


def _read_files(paths: "list[Path]", findings, what: str) -> "list[str]":
    texts = []
    for p in paths:
        try:
            texts.append(p.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            findings.append({
                "check": "input-unreadable", "severity": "high",
                "object": str(p), "field": "-",
                "message": f"{what} tidak terbaca: {exc}",
            })
    return texts


# ---------------------------------------------------------------- sshd

_SSHD_CHECKS = [
    # (param, (nilai_benar...), severity_salah, severity_absen, pesan)
    ("PermitRootLogin", {"no"}, "high", "medium",
     "root login via SSH harus 'no' (skill sumber 5.2); "
     "absen = default OpenSSH 'prohibit-password' — masih mengizinkan "
     "kunci root"),
    ("PasswordAuthentication", {"no"}, "high", "medium",
     "autentikasi password sebaiknya 'no' (kunci saja); absen = "
     "distro banyak yang default 'yes'"),
    ("PermitEmptyPasswords", {"no"}, "high", "medium",
     "password kosong wajib 'no'; absen = default OpenSSH 'no' pada "
     "rilis modern, verifikasi eksplisit"),
    ("MaxAuthTries", None, "medium", "medium",
     "MaxAuthTries sebaiknya <= 4 (skill sumber 5.2)"),
    ("LoginGraceTime", None, "medium", "medium",
     "LoginGraceTime sebaiknya <= 60 detik"),
    ("MaxStartups", None, "medium", "low",
     "MaxStartups pola awal:rate:full, acuan 10:30:60"),
    ("X11Forwarding", {"no"}, "medium", "low",
     "X11Forwarding sebaiknya 'no' di server"),
    ("AllowTcpForwarding", {"no"}, "medium", "low",
     "AllowTcpForwarding sebaiknya 'no' bila tak dipakai"),
    ("LogLevel", {"VERBOSE"}, "low", "low",
     "LogLevel sebaiknya VERBOSE agar proses login tercatat"),
    ("ClientAliveInterval", None, "low", "low",
     "ClientAliveInterval 300 + CountMax 3 (acuan sumber); 0 = idle "
     "tanpa batas"),
]


def audit_sshd(text: str, src: str, add) -> None:
    rows = _read_kv(text, "space")
    for param, good, sev_wrong, sev_absent, message in _SSHD_CHECKS:
        val, commented = _first_win(rows, param)
        field = f"{src}:{param}"
        if val is None:
            add(f"sshd-{param.lower().replace('_', '-')}", sev_absent,
                field, param, f"{param} tidak ditemukan (aktif) — "
                f"{message}")
            continue
        if good is not None:
            good_l = {g.lower() for g in good}
            if val.lower() not in good_l:
                add(f"sshd-{param.lower().replace('_', '-')}", sev_wrong,
                    field, f"{param} {val}", f"{param} = '{val}' — "
                    f"{message}")
            continue
        # parameter bernilai angka / pola
        if param == "MaxAuthTries":
            try:
                if int(val) > 4:
                    add("sshd-maxauthtries", "medium", field,
                        f"{param} {val}", f"MaxAuthTries = {val} > 4")
            except ValueError:
                add("sshd-maxauthtries", "medium", field,
                    f"{param} {val}", f"nilai tak terurai: '{val}'")
        elif param == "LoginGraceTime":
            secs = 0 if val.lower() == "0" else _seconds(val)
            if secs is None or secs > 60:
                add("sshd-login-gracetime", "medium", field,
                    f"{param} {val}", f"LoginGraceTime = '{val}' — "
                    "harus <= 60s (0/unlimited = tanpa batas)")
        elif param == "MaxStartups":
            start = val.split(":")[0]
            try:
                if int(start) > 10:
                    add("sshd-maxstartups", "medium", field,
                        f"{param} {val}",
                        f"ambang awal {start} > 10")
            except ValueError:
                add("sshd-maxstartups", "medium", field,
                    f"{param} {val}", f"nilai tak terurai: '{val}'")
        elif param == "ClientAliveInterval":
            try:
                if int(val) == 0:
                    add("sshd-clientalive", "low", field,
                        f"{param} {val}", "keepalive SSH dinonaktifkan")
            except ValueError:
                add("sshd-clientalive", "low", field,
                    f"{param} {val}", f"nilai tak terurai: '{val}'")
    if any(k.lower() == "include" for k, _, _ in rows):
        add("sshd-include-unaudited", "low", f"{src}:Include", "Include",
            "sshd_config memuat Include — berkas acuan tidak diberikan "
            "ke tool; nilai di sana bisa menimpa cek di sini (first-wins "
            "per parameter pada berkas gabungan)")


def _seconds(val: str) -> "int | None":
    val = val.strip().lower()
    if val in ("none", "unlimited"):
        return None
    try:
        return int(val)
    except ValueError:
        table = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
        if val and val[-1] in table and val[:-1].isdigit():
            return int(val[:-1]) * table[val[-1]]
        return None


# ---------------------------------------------------------------- sysctl

_SYSCTL_EXPECT = {
    "net.ipv4.ip_forward": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.secure_redirects": "0",
    "net.ipv4.conf.default.secure_redirects": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.conf.default.log_martians": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv6.conf.all.accept_ra": "0",
    "net.ipv6.conf.default.accept_ra": "0",
}


def audit_sysctl(text: str, src: str, add) -> None:
    rows = _read_kv(text, "=")
    values: "dict[str, str]" = {}
    for k, v, commented in rows:
        if commented:
            continue
        values[_normalize_sysctl_key(k)] = v
    for key, expected in _SYSCTL_EXPECT.items():
        val = values.get(key)
        field = f"{src}:{key}"
        if val is None:
            add("sysctl-param", "medium", field, key,
                f"{key} tidak ditemukan (harus {expected}) — pastikan "
                "ekspor/berkas yang diberikan mencakup parameter ini")
        elif val != expected:
            add("sysctl-param", "medium", field, f"{key}={val}",
                f"{key} = {val}, seharusnya {expected}")


# ------------------------------------------------------------ pwquality

def audit_pwquality(text: str, src: str, add) -> None:
    rows = _read_kv(text, "=")
    val, _ = _last_win(rows, "minlen")
    field = f"{src}:minlen"
    if val is None:
        add("pwq-minlen", "medium", field, "minlen",
            "minlen tidak ditemukan — acuan >= 14 (skill sumber 5.3)")
    else:
        try:
            if int(val) < 14:
                add("pwq-minlen", "medium", field, f"minlen={val}",
                    f"minlen = {val} < 14")
        except ValueError:
            add("pwq-minlen", "medium", field, f"minlen={val}",
                f"nilai tak terurai: '{val}'")
    for cls in ("dcredit", "ucredit", "ocredit", "lcredit"):
        val, _ = _last_win(rows, cls)
        field = f"{src}:{cls}"
        if val is None or val.strip() != "-1":
            add("pwq-class-credit", "low", field,
                cls + (f"={val}" if val else ""),
                f"{cls} sebaiknya -1 (wajib kelas karakter); "
                f"nilai sekarang: {val or 'absen'}")


# ----------------------------------------------------------- login.defs

def audit_login_defs(text: str, src: str, add) -> None:
    rows = _read_kv(text, "space")
    val, _ = _last_win(rows, "PASS_MAX_DAYS")
    if val is None or not val.isdigit() or int(val) > 365:
        add("ldefs-pass-max-days", "medium", f"{src}:PASS_MAX_DAYS",
            f"PASS_MAX_DAYS={val or 'absen'}",
            "PASS_MAX_DAYS <= 365 (acuan sumber); absen = tergantung "
            "distro")
    val, _ = _last_win(rows, "PASS_MIN_DAYS")
    if val is None or not val.isdigit() or int(val) < 1:
        add("ldefs-pass-min-days", "low", f"{src}:PASS_MIN_DAYS",
            f"PASS_MIN_DAYS={val or 'absen'}",
            "PASS_MIN_DAYS >= 1 mencegah rotasi instan")
    val, _ = _last_win(rows, "PASS_WARN_AGE")
    if val is None or not val.isdigit() or int(val) < 7:
        add("ldefs-pass-warn-age", "low", f"{src}:PASS_WARN_AGE",
            f"PASS_WARN_AGE={val or 'absen'}",
            "PASS_WARN_AGE >= 7 hari")
    val, _ = _last_win(rows, "ENCRYPT_METHOD")
    if val is None:
        add("ldefs-encrypt-method", "low", f"{src}:ENCRYPT_METHOD",
            "ENCRYPT_METHOD=absen",
            "ENCRYPT_METHOD eksplisit (SHA512/YESCRYPT)")
    elif val.upper() not in ("SHA512", "YESCRYPT"):
        add("ldefs-encrypt-method", "medium",
            f"{src}:ENCRYPT_METHOD", f"ENCRYPT_METHOD={val}",
            f"ENCRYPT_METHOD = '{val}' lemah — gunakan SHA512/YESCRYPT")


# ---------------------------------------------------------------- main

def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sshd", nargs="*", type=Path, default=[],
                    metavar="FILE", help="sshd_config (boleh beberapa)")
    ap.add_argument("--sysctl", nargs="*", type=Path, default=[],
                    metavar="FILE",
                    help="sysctl.conf / gabungan sysctl.d / dump sysctl -a")
    ap.add_argument("--pwquality", nargs="*", type=Path, default=[],
                    metavar="FILE", help="pwquality.conf")
    ap.add_argument("--login-defs", nargs="*", type=Path, default=[],
                    metavar="FILE", help="login.defs")
    ap.add_argument("--fail-on", choices=SEVERITY_ORDER, default="medium")
    ap.add_argument("--allow-check", action="append", default=[],
                    metavar="NAME")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    if not (args.sshd or args.sysctl or args.pwquality
            or args.login_defs):
        print(json.dumps({
            "schema": SCHEMA,
            "error": "berikan minimal satu kelompok berkas "
                     "(--sshd/--sysctl/--pwquality/--login-defs) — "
                     "fail-closed",
        }), file=sys.stderr)
        return 2

    allowed = set(args.allow_check)
    findings: "list[dict]" = []

    def add(check, severity, obj, field, message):
        if check in allowed:
            return
        findings.append({"check": check, "severity": severity,
                         "object": obj, "field": field,
                         "message": message})

    grouped = [("sshd", args.sshd, audit_sshd),
               ("sysctl", args.sysctl, audit_sysctl),
               ("pwquality", args.pwquality, audit_pwquality),
               ("login.defs", args.login_defs, audit_login_defs)]
    files_total = 0
    for label, paths, fn in grouped:
        texts = _read_files(paths, findings, label)
        files_total += len(texts)
        for p, text in zip(paths, texts):
            fn(text, p.name, add)

    threshold = SEVERITY_ORDER[args.fail_on]
    hit = any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold
              for f in findings)
    notes = [
        "audit statis atas berkas yang DIKUMPUL — bukan hasil live host; "
        "efektivitas berlaku selama berkas masih yang dipakai host",
        "sshd: nilai PERTAMA per parameter yang menang (semantik "
        "OpenSSH); sysctl: nilai TERAKHIR yang menang (semaktik sysctl.d)",
        "parameter absen selalu jadi temuan (fail-closed) — tidak pernah "
        "diasumsikan 'sudah aman default'",
        "blok Match sshd_config tidak diurai terpisah — arahan di dalam "
        "Match diperlakukan sebagai berlaku umum; cek manual bila host "
        "memakai Match",
        "remedi live (systemctl/sed/sysctl -w) = di luar tool — skill "
        "sumber memegang runbook itu",
    ]
    if allowed:
        notes.append(f"check disaring: {', '.join(sorted(allowed))}")
    report = {
        "schema": SCHEMA,
        "summary": {
            "files_read": files_total,
            "findings": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ("high", "medium", "low")
            },
        },
        "findings": sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0),
                           f["object"], f["check"]),
        ),
        "notes": notes,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
