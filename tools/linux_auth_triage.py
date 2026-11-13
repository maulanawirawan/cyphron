r"""[SAFETY: read-only] linux_auth_triage — triase OFFLINE log autentikasi
Linux (auth.log / secure gaya syslog klasik ATAU ekspor jurnal
ISO-8601): sesi SSH (accepted/failed), sudo, su, pam failure, perubahan
akun (useradd/usermod/userdel), CRON — rekonstruksi sesi + deteksi brute
force dari teks log. TANPA jaringan.

Pembagian ranah (TIDAK diduplikasi):
  - triase log Windows (4624/4625/4688/Sysmon) -> win_logon_triage,
    sysmon_triage, win_auth_triage
  - sisi konfigurasi persistensi Linux (cron/systemd/authorized_keys)
    -> linux_persist_scan (blok ini, #0849)
  - integritas file -> aide_change_triage
  - di sini: teks log autentikasi Linux.

Input -> mekanisme -> output:
  - Input : satu atau lebih file log teks (baris "syslog klasik":
            "Nov  8 14:23:01 host proc[pid]: pesan", ATAU gaya
            jurnal/rsyslog ISO-8601: "2026-11-08T14:23:01.123+00:00
            host proc[pid]: pesan"). Baca-saja.
  - Mekanisme: parse header (timestamp 2 gaya, host, proc[pid]) lalu
            pola pesan sshd/sudo/su/pam/useradd/usermod/CRON; agregasi
            kegagalan per sumber IP -> brute force; kegagalan >= 3 pada
            pasangan (IP,user) yang LALU berhasil (urutan file) = sinyal
            kompromi klasik.
  - Output: JSON {schema, stats, events, findings, notes}; finding =
            {check, severity, message, evidence, (+user/source_ip)}.

Cek:
  bruteforce-source    (high/medium): >= --min-fail kegagalan dari IP
                       sama (high bila >= 2x ambang atau >= 5 user unik).
  bruteforce-success   (high): >= 3 kegagalan lalu Accepted pada
                       pasangan (ip,user) yang sama (urutan file) —
                       kandidat kompromi.
  root-password-login  (high): Accepted password untuk root via SSH.
  sudo-group-add       (high): usermod menambah user ke sudo/wheel/admin.
  new-account          (medium): useradd akun baru dgn shell interaktif
                       (nologin = info).
  account-removal      (info): userdel menghapus akun.
  su-failure           (medium): FAILED su / authentication failure su.
  publickey-root-login (info): Accepted publickey untuk root.
  line-unparsed        (high): baris dari proc keamanan dikenal
                       (sshd/sudo/su/useradd/usermod/userdel/groupadd/
                       passwd/CRON) yang polanya tidak dikenali —
                       fail-closed, TIDAK dianggap bersih.

Fail-closed:
  - file tidak ada / tidak terbaca -> exit 2.
  - tidak ada satu baris pun ber-header syslog/ISO yang ter-parse ->
    exit 2 (bukan log autentikasi).
  - baris proc keamanan yang tak ter-parse -> line-unparsed (tetap
    dilaporkan; tidak pernah dibuang diam-diam).
  - format klasik tanpa tahun = keterbatasan tercatat di notes (bukan
    kebersihan).

Anti-FP: --allow-ip IP/PREFIX (boleh diulang) menyaring sumber sah
(jumphost, pemindai internal); jumlah saringan dicatat di
stats.allowed_filtered — tidak dipendam.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error input.

Pemakaian:
  python tools/linux_auth_triage.py --log auth.log --out triage.json
  python tools/linux_auth_triage.py --log secure-1 --log secure-2 \
      --min-fail 5 --allow-ip 10.0.0.0/8
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.linux-auth-triage/1"
MAX_FILE_BYTES = 64 * 1024 * 1024

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# proc yang pesannya WAJIB dikenali (fail-closed bila lolos pola)
SECURITY_PROCS = {
    "sshd", "sshd-session", "sudo", "sudo-i", "su", "su-l",
    "useradd", "adduser", "usermod", "userdel", "groupadd",
    "passwd", "CRON", "CROND", "cron",
}
# pesan sshd yang diketahui & bukan sinyal (bukan unparsed)
SSHD_NOISE = (
    "received disconnect", "disconnected from", "connection closed",
    "connection reset", "connection from", "banner exchange",
    "subsystem request", "error: kex", "error: maximum",
    "unable to negotiate", "server listening", "starting session",
    "closing connection", "pam_unix(sshd:session)", "pam_unix(sshd:auth)",
    "possible break-in", "refused connect", "set /proc/self/oom_score_adj",
)
# noise pam lintas-proc (sesi) — dicek global sebelum cabang proc
PAM_NOISE = (
    "pam_unix(sshd:session)", "pam_unix(su:session)",
    "pam_unix(sudo:session)", "pam_unix(cron:session)",
    "pam_unix(crond:session)", "pam_unix(systemd-user:session)",
    "session opened for user", "session closed for user",
    "new session ", "removed session ",
)

RE_SYSLOG = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
    r"([\w./-]+)(?:\[(\d+)\])?:\s(.*)$")
RE_ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[+-]\d{2}:?\d{2}|Z)?)\s+(\S+)\s+([\w./-]+)(?:\[(\d+)\])?:\s(.*)$")

RE_ACCEPT = re.compile(
    r"^Accepted\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+"
    r"from\s+(\S+)\s+port\s+(\d+)")
RE_FAILED = re.compile(
    r"^Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+"
    r"from\s+(\S+)\s+port\s+(\d+)")
RE_INVALID = re.compile(r"^Invalid user\s+(\S+)\s+from\s+(\S+)")
RE_TOO_MANY = re.compile(
    r"^Too many authentication failures for (?:invalid user\s+)?(\S+)"
    r"\s+from\s+(\S+)")
RE_SUDO = re.compile(r"^(\S+)\s*:\s*TTY=\S+.*?COMMAND=(.*)$")
RE_SUDO_FAILS = re.compile(r"^(\S+)\s*:\s*(\d+)\s+incorrect password")
RE_SU_TO = re.compile(r"^\(to (\S+)\)\s+(\S+) on ")
RE_SU_FAIL = re.compile(r"^FAILED su for (\S+) by (\S+)")
RE_PAM_FAIL = re.compile(
    r"^(?:\(pam_unix\)|pam_unix\([^)]*\)):?\s*authentication failure;.*?"
    r"rhost=(\S*)\s.*?user=(\S*)\s*$")
RE_USERADD = re.compile(r"^new user: name=(\S+),.*shell=(\S+)")
RE_GROUPADD = re.compile(r"^new group: name=(\S+)")
RE_USERMOD_ADD = re.compile(r"^add '(\S+)' to group '(\S+)'")
RE_USERMOD_SHELL = re.compile(r"^change user '(\S+)' shell")
RE_USERDEL = re.compile(r"^delete user '(\S+)'")
RE_CRON = re.compile(r"^\((\S+)\)\s+CMD\s+\((.*)\)\s*$")

PRIV_GROUPS = {"sudo", "wheel", "admin", "root"}


def _parse_header(line: str) -> "tuple[str, str, str] | None":
    """(proc, ts, message) dari dua gaya header syslog."""
    m = RE_ISO.match(line)
    if m:
        return m.group(3), m.group(1), m.group(5)
    m = RE_SYSLOG.match(line)
    if m:
        return m.group(5), f"{m.group(1)} {m.group(2)} {m.group(3)}", m.group(7)
    return None


def _scan_lines(lines: "list[str]") -> "tuple[list[dict], list[dict], dict]":
    """Parse baris log -> (events, findings, stats)."""
    events: "list[dict]" = []
    findings: "list[dict]" = []
    stats = {
        "lines_total": 0, "lines_parsed_header": 0,
        "lines_ignored_noise": 0, "lines_other_proc": 0,
        "line_unparsed": 0,
        "accepted": 0, "failed": 0, "invalid_user": 0,
        "sudo_commands": 0, "su_sessions": 0, "auth_failures": 0,
        "account_changes": 0, "cron_execs": 0,
    }

    def add(check: str, severity: str, message: str, *,
            ts: str = "", proc: str = "", user: str = "",
            source_ip: str = "", extra: "dict | None" = None) -> None:
        f = {"check": check, "severity": severity, "message": message,
             "evidence": f"{ts} {proc}: {message[:160]}".strip()}
        if user:
            f["user"] = user
        if source_ip:
            f["source_ip"] = source_ip
        if extra:
            f.update(extra)
        findings.append(f)

    for raw in lines:
        stats["lines_total"] += 1
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        head = _parse_header(line)
        if head is None:
            continue  # bukan header syslog (banner/lanjutan) — dihitung saja
        proc, ts, msg = head
        stats["lines_parsed_header"] += 1
        low = msg.strip().lower()
        base = {"ts": ts, "proc": proc}

        if low.startswith(PAM_NOISE):
            stats["lines_ignored_noise"] += 1
            continue

        if proc in ("sshd", "sshd-session"):
            m = RE_ACCEPT.match(msg.strip())
            if m:
                method, user, ip, port = m.groups()
                stats["accepted"] += 1
                events.append({**base, "kind": "accepted", "method": method,
                               "user": user, "ip": ip, "port": port})
                if user == "root" and method == "password":
                    add("root-password-login", "high",
                        "login SSH root BERHASIL memakai password — "
                        "larang direct-root SSH; verifikasi aktor.",
                        ts=ts, proc=proc, user=user, source_ip=ip)
                elif user == "root":
                    add("publickey-root-login", "info",
                        "login SSH root via publickey — sah di lab, "
                        "catat utk baseline.", ts=ts, proc=proc,
                        user=user, source_ip=ip)
                continue
            m = RE_FAILED.match(msg.strip())
            if m:
                method, user, ip, port = m.groups()
                stats["failed"] += 1
                events.append({**base, "kind": "failed", "method": method,
                               "user": user, "ip": ip, "port": port})
                continue
            m = RE_INVALID.match(msg.strip())
            if m:
                stats["invalid_user"] += 1
                events.append({**base, "kind": "invalid_user",
                               "user": m.group(1), "ip": m.group(2)})
                continue
            m = RE_TOO_MANY.match(msg.strip())
            if m:
                stats["failed"] += 1
                events.append({**base, "kind": "failed",
                               "method": "too-many", "user": m.group(1),
                               "ip": m.group(2), "port": ""})
                continue
            if low.startswith(SSHD_NOISE):
                stats["lines_ignored_noise"] += 1
                continue
            add("line-unparsed", "high",
                f"baris {proc} tidak dikenali polanya (fail-closed) — "
                "cek format/versi OpenSSH.", ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        if proc in ("sudo", "sudo-i"):
            m = RE_SUDO.match(msg.strip())
            if m:
                stats["sudo_commands"] += 1
                events.append({**base, "kind": "sudo_cmd",
                               "user": m.group(1), "command": m.group(2)})
                continue
            m = RE_SUDO_FAILS.match(msg.strip())
            if m:
                stats["auth_failures"] += 1
                events.append({**base, "kind": "sudo_auth_fail",
                               "user": m.group(1), "attempts": m.group(2)})
                continue
            if low.startswith("pam_unix("):
                stats["lines_ignored_noise"] += 1
                continue
            add("line-unparsed", "high",
                "baris sudo tidak dikenali polanya (fail-closed).",
                ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        if proc in ("su", "su-l"):
            m = RE_SU_TO.match(msg.strip())
            if m:
                stats["su_sessions"] += 1
                events.append({**base, "kind": "su_session",
                               "to": m.group(1), "user": m.group(2)})
                continue
            m = RE_SU_FAIL.match(msg.strip())
            if m:
                add("su-failure", "medium",
                    f"su GAGAL ke '{m.group(1)}' oleh '{m.group(2)}' — "
                    "percobaan eskalasi tercatat.", ts=ts, proc=proc,
                    user=m.group(2))
                continue
            m = RE_PAM_FAIL.match(msg.strip())
            if m:
                stats["auth_failures"] += 1
                events.append({**base, "kind": "auth_failure",
                               "user": m.group(2),
                               "rhost": m.group(1)})
                add("su-failure", "medium",
                    "autentikasi su GAGAL (pam) untuk "
                    f"'{m.group(2) or '?'}' — percobaan eskalasi "
                    "tercatat.", ts=ts, proc=proc,
                    user=m.group(2) or "")
                continue
            add("line-unparsed", "high",
                "baris su tidak dikenali polanya (fail-closed).",
                ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        if proc in ("useradd", "adduser"):
            m = RE_USERADD.match(msg.strip())
            if m:
                stats["account_changes"] += 1
                sev = "info" if "nologin" in m.group(2) else "medium"
                add("new-account", sev,
                    f"akun baru '{m.group(1)}' (shell={m.group(2)}) — "
                    "verifikasi kreator & kebutuhan.", ts=ts, proc=proc,
                    user=m.group(1), extra={"shell": m.group(2)})
                continue
            add("line-unparsed", "high",
                "baris useradd tidak dikenali polanya (fail-closed).",
                ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        if proc == "groupadd":
            m = RE_GROUPADD.match(msg.strip())
            if m:
                stats["account_changes"] += 1
                events.append({**base, "kind": "group_add",
                               "group": m.group(1)})
                continue
            add("line-unparsed", "high",
                "baris groupadd tidak dikenali (fail-closed).",
                ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        if proc == "usermod":
            m = RE_USERMOD_ADD.match(msg.strip())
            if m:
                user, group = m.groups()
                stats["account_changes"] += 1
                if group.lower() in PRIV_GROUPS:
                    add("sudo-group-add", "high",
                        f"'{user}' ditambahkan ke grup '{group}' — jalur "
                        "eskalasi ke root; verifikasi persetujuan.",
                        ts=ts, proc=proc, user=user,
                        extra={"group": group})
                else:
                    events.append({**base, "kind": "group_member_add",
                                   "user": user, "group": group})
                continue
            if RE_USERMOD_SHELL.match(msg.strip()) or low.startswith(
                    ("change user '", "lock '", "unlock '")):
                stats["account_changes"] += 1
                continue
            add("line-unparsed", "high",
                "baris usermod tidak dikenali polanya (fail-closed).",
                ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        if proc == "userdel":
            m = RE_USERDEL.match(msg.strip())
            if m:
                add("account-removal", "info",
                    f"akun '{m.group(1)}' dihapus — jejak audit dicatat.",
                    ts=ts, proc=proc, user=m.group(1))
                continue
            if low.startswith(("remove group", "delete shadow group")):
                stats["lines_ignored_noise"] += 1
                continue
            add("line-unparsed", "high",
                "baris userdel tidak dikenali (fail-closed).",
                ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        if proc == "passwd":
            if "password changed" in low or "changed password" in low:
                stats["account_changes"] += 1
                continue
            add("line-unparsed", "high",
                "baris passwd tidak dikenali (fail-closed).",
                ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        if proc in ("CRON", "CROND", "cron"):
            m = RE_CRON.match(msg.strip())
            if m:
                stats["cron_execs"] += 1
                events.append({**base, "kind": "cron_exec",
                               "user": m.group(1), "command": m.group(2)})
                continue
            add("line-unparsed", "high",
                "baris CRON tidak dikenali polanya (fail-closed).",
                ts=ts, proc=proc)
            stats["line_unparsed"] += 1
            continue

        stats["lines_other_proc"] += 1
    return events, findings, stats


def detect(events: "list[dict]", min_fail: int) -> "list[dict]":
    """Deteksi agregat urutan-file: brute force per sumber + fail->ok."""
    findings: "list[dict]" = []
    fails_by_ip: "dict[str, list[dict]]" = {}
    fail_seq: "dict[tuple[str, str], int]" = {}

    for ev in events:
        kind = ev.get("kind")
        if kind == "failed":
            fails_by_ip.setdefault(ev["ip"], []).append(ev)
            key = (ev["ip"], ev.get("user", ""))
            fail_seq[key] = fail_seq.get(key, 0) + 1
        elif kind == "accepted":
            key = (ev["ip"], ev.get("user", ""))
            n = fail_seq.get(key, 0)
            if n >= 3:
                findings.append({
                    "check": "bruteforce-success", "severity": "high",
                    "source_ip": ev["ip"], "user": ev.get("user", ""),
                    "message": f"{n} kegagalan lalu LOGIN BERHASIL untuk "
                               f"'{ev.get('user', '')}' dari {ev['ip']} — "
                               "kandidat kompromi; tindak lanjuti sesi & "
                               "perintahnya.",
                    "evidence": f"fails={n} then accepted "
                                f"({ev.get('method', '')})",
                })
            fail_seq[key] = 0

    for ip, evs in sorted(fails_by_ip.items()):
        if len(evs) < min_fail:
            continue
        users = sorted({e.get("user", "") for e in evs if e.get("user")})
        sev = "high" if (len(evs) >= 2 * min_fail
                         or len(users) >= 5) else "medium"
        findings.append({
            "check": "bruteforce-source", "severity": sev, "source_ip": ip,
            "message": f"{len(evs)} kegagalan autentikasi dari {ip} "
                       f"(>= {min_fail}); {len(users)} user unik "
                       f"{users[:5]}",
            "evidence": f"failed={len(evs)} users={len(users)}",
        })
    return findings


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase log autentikasi Linux offline, nol jaringan.")
    ap.add_argument("--log", action="append", required=True,
                    metavar="FILE",
                    help="file auth.log/secure (boleh diulang)")
    ap.add_argument("--min-fail", type=int, default=10,
                    help="ambang kegagalan per sumber utk bruteforce "
                         "(default 10)")
    ap.add_argument("--allow-ip", action="append", default=[],
                    metavar="IP/PREFIX",
                    help="abaikan temuan dari sumber ini (bisa diulang)")
    ap.add_argument("--fail-on", default="medium",
                    choices=["info", "low", "medium", "high", "critical"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    lines: "list[str]" = []
    for f in args.log:
        p = Path(f)
        try:
            if not p.is_file():
                raise ValueError(f"file tidak ada: {p}")
            if p.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"file terlalu besar: {p}")
            lines.extend(p.read_text(encoding="utf-8",
                                     errors="replace").splitlines())
        except ValueError as exc:
            print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
                  file=sys.stderr)
            return 2

    events, findings, stats = _scan_lines(lines)
    if stats["lines_parsed_header"] == 0:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "tidak ada baris ber-header syslog/ISO yang "
                     "ter-parse — kemungkinan bukan log autentikasi "
                     "Linux (fail-closed)",
        }), file=sys.stderr)
        return 2
    stats["events"] = {k: stats[k] for k in
                       ("accepted", "failed", "invalid_user",
                        "sudo_commands", "su_sessions", "auth_failures",
                        "account_changes", "cron_execs")}

    findings.extend(detect(events, max(1, args.min_fail)))

    allow = tuple(a.strip() for a in args.allow_ip if a.strip())
    if allow:
        kept = []
        for f in findings:
            ip = str(f.get("source_ip", ""))
            if ip and any(ip == a or ip.startswith(a)
                          for a in allow):
                stats["allowed_filtered"] = \
                    stats.get("allowed_filtered", 0) + 1
                continue
            kept.append(f)
        findings = kept

    threshold = SEV_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEV_ORDER.get(f["severity"], 0) >= threshold]

    notes = [
        "format klasik syslog TANPA tahun — keterbatasan format, bukan "
        "kebersihan; gabungkan dgn konteks rotasi log.",
        "tampilan sisi LOG; sisi konfigurasi persistensi Linux "
        "(cron/systemd/authorized_keys/ld.so.preload) = "
        "linux_persist_scan.",
        "perintah sudo & eksekusi CRON terekam di events (bukan temuan) "
        "— tinjau manual utk lolbin/payload.",
        "baris proc keamanan yang tak ter-parse dilaporkan sebagai "
        "line-unparsed (fail-closed), tidak pernah dibuang diam-diam.",
    ]
    if stats.get("allowed_filtered"):
        notes.append(f"{stats['allowed_filtered']} temuan disaring via "
                     "--allow-ip — saringan dicatat, tidak dipendam.")

    report = {
        "schema": SCHEMA,
        "stats": stats,
        "events": events[-500:],
        "findings": sorted(
            findings,
            key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                           f["check"], f.get("source_ip", ""),
                           f.get("user", ""))),
        "notes": notes,
    }
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
