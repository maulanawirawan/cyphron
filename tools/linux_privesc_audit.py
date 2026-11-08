r"""[AUDIT: read-only] linux_privesc_audit — audit OFFLINE vektor
privilege-escalation Linux dari koleksi rootfs (salinan forensik/arsip
tar) dan/atau daftar hasil enumerasi (find SUID/SGID, getcap): sudoers
(NOPASSWD + perintah berbahaya, wildcard, runas ALL), akun UID-0 ganda,
keanggotaan grup root-ekuivalen (docker/lxd), inventaris SUID/SGID di
lokasi tak lazim / direktori writable, file capability berisiko, export
NFS no_root_squash, berkas world-writable di /etc & unit systemd, target
cron yang writable + wildcard injection, dan PATH directory writable.
TANPA jaringan.

Mengisi antrean port SKILL-PORT-QUEUE #0876 (mukul975/
Anthropic-Cybersecurity-Skills 'performing-privilege-escalation-on-
linux'; atribusi konsep vektor T1548.001/T1548.003/T1543.002/T1053.003,
lisensi sumber Apache-2.0). Skill sumber = runbook enumerasi LIVE pada
host yang sudah diakses sah (LinPEAS/LinEnum/GTFOBins); inti
deterministik yang diekstrak di sini = AUDIT MISKONFIGURASI dari
koleksi/file-list yang sudah diambil — from scratch, tanpa menyalin
kode sumber maupun menjalankan enumerasi live.

Pembagian ranah (TIDAK diduplikasi):
  - konten persistensi jahat di cron/unit/profile/authkeys/preload ->
    linux_persist_scan (sudutnya "artefak persistence", bukan
    writability); di sini cron dibaca hanya untuk menilai TARGET yang
    bisa ditulis akun biasa (privesc) & wildcard-args.
  - hardening konfigurasi sshd/sysctl/pwquality/login.defs ->
    linux_cis_audit.
  - triase log auth -> linux_auth_triage.
  - enumerasi live di host hidup (LinPEAS/pspy/GTFOBins lookup) = sisi
    eksekusi skill sumber (tidak diport) — koleksi dulu di lab, audit
    di sini.

Input -> mekanisme -> output:
  - Input : --root DIR (rootfs copy: etc/sudoers, etc/sudoers.d/,
            etc/passwd, etc/shadow, etc/group, etc/exports, etc/crontab,
            etc/cron.d/, var/spool/cron/, etc/profile*, etc/environment,
            walk mode SUID/SGID via lstat + xattr security.capability).
            Opsional: --suid-list FILE (stdout `find / -perm -4000 -o
            -perm -2000 -type f` ATAU `ls -l`), --cap-list FILE (stdout
            `getcap -r /`). Baca-saja; butuh minimal satu sumber.
  - Mekanisme: tiap sumber diparse -> cek deterministik per vektor ->
            temuan severity + poc (baris/path sumber).
  - Output: JSON {schema, stats, fail_on, findings, notes, verdict}.

Cek:
  sudo-nopasswd-risky   (high)  : NOPASSWD utk perintah kelas GTFOBins
                         (find/vim/less/awk/python/perl/bash/docker/
                         mount/env/tar/cp/tee/chmod dsb. — tabel sendiri).
  sudo-nopasswd-all     (high)  : NOPASSWD + command ALL.
  sudo-wildcard-arg     (high)  : wildcard di argumen spec perintah sudo.
  sudo-runas-all        (medium): (ALL)/(ALL : ALL) tanpa NOPASSWD.
  sudo-nopasswd-other   (low)   : NOPASSWD perintah di luar tabel
                         berbahaya (review).
  sudoers-missing       (medium): --root diberikan tapi sudoers tak
                         terbaca (collection-incomplete, fail-closed).
  sudoers-unparsed      (info)  : baris spec tak ter-parse dihitung.
  uid-0-account         (high)  : akun UID 0 selain root di /etc/passwd.
  shadow-empty-password (high)  : field hash kosong di /etc/shadow.
  risky-group-membership(high/med): anggota docker/lxd (high — root-
                         ekuivalen) / wheel/sudo/admin utk UID>=1000
                         (medium — review least-privilege).
  suid-writable-dir     (high)  : SUID dengan direktori induk world/
                         group-writable tanpa sticky bit.
  suid-writable-file    (high)  : berkas SUID itu sendiri world-writable.
  suid-unexpected-location (medium): SUID di luar prefiks standar.
  sgid-writable-dir     (medium): padanan SGID.
  sgid-unexpected-location (medium).
  sgid-writable-file    (high)  : berkas SGID world-writable.
  filecap-risky         (high)  : cap_setuid/cap_dac_override/
                         cap_dac_read_search/cap_sys_admin/cap_sys_module/
                         cap_sys_ptrace/cap_net_admin/cap_net_raw/
                         cap_mknod/cap_bpf/cap_setfcap dsb.
  filecap-unexpected    (low)   : cap lain di luar prefiks standar.
  nfs-no-root-squash    (high)  : /etc/exports berisi no_root_squash.
  nfs-world-export      (medium): export NFS ke host '*'.
  worldwritable-etc     (medium): berkas world-writable di /etc.
  worldwritable-unit    (high)  : world-writable di pohon unit systemd/
                         init.d (dieksekusi root).
  cron-writable-target  (high)  : path dalam perintah cron yang world/
                         group-writable tanpa sticky.
  cron-wildcard-args    (medium): token '*' telanjang dalam perintah cron.
  path-dir-writable     (medium): direktori PATH (profile/environment)
                         world/group-writable.
  collection-incomplete (medium): walk terpotong / sumber inti tak
                         terbaca — dicatat, bukan dianggap bersih.

Fail-closed:
  - --root tak ada / bukan direktori -> exit 2.
  - tanpa --root dan tanpa --suid-list/--cap-list -> exit 2.
  - --suid-list/--cap-list yang diberikan tapi tak terbaca ATAU tanpa
    satu pun entri yang ter-parse -> exit 2 (fail-closed, bukan "aman").
  - sudoers hilang = temuan collection-incomplete (bukan "aman").
  - xattr capability tak terbaca = dihitung & dilaporkan di notes.
  - cap_net_raw/cap_net_bind_service di luar prefiks standar = low
    (filecap-unexpected) — bukan high, pengguna sah umum (ping).

Anti-FP: tabel perintah berbahaya hanya relevan dgn NOPASSWD; wildcard
hanya di spec perintah (bukan data); prefiks standar eksplisit
(/usr/bin /bin /usr/sbin /sbin /usr/lib /usr/lib64 /usr/libexec);
--allow-path utk pengecualian tercatat (bukan silent); cap pada prefiks
standar tidak ditemukan kecuali masuk set risky.

Keterbatasan: cek berbasis mode (SUID/SGID/world-writable) mengasumsikan
koleksi rootfs dgn mode POSIX terpreservasi (tar --xattrs/--acls, rsync
-a). Menjalankan --root ke salinan yang dibuat TANPA preservasi mode
(mis. salinan Windows biasa — semua dir 0o777, SUID hilang) menghasilkan
temuan world-writable palsu & kehilangan cek SUID — gunakan --suid-list/
--cap-list dari enumerasi host asli sbg sumber kebenaran mode.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error input.

Pemakaian:
  python tools/linux_privesc_audit.py --root /collections/host01
  python tools/linux_privesc_audit.py --root /c/host01 \
      --suid-list find.out --cap-list getcap.out --out audit.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat as statmod
import struct
import sys
from pathlib import Path

SCHEMA = "secai.linux-privesc-audit/1"

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Prefiks lokasi SUID/SGID/cap "dikenal baik" (distribusi standar).
STANDARD_PREFIXES = (
    "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    "/usr/lib", "/usr/lib64", "/usr/libexec",
)

# Kelas perintah yang memberi shell/penulisan berkas bila dijalankan
# root (konsep GTFOBins — tabel ringkas milik sendiri).
RISKY_SUDO_COMMANDS = {
    "find", "vim", "vi", "less", "more", "nano", "awk", "sed", "perl",
    "python", "python3", "python2", "ruby", "php", "lua", "node",
    "bash", "sh", "zsh", "dash", "ash", "ksh", "csh", "tcsh",
    "nmap", "tcpdump", "openssl", "docker", "podman", "lxc", "mount",
    "umount", "env", "nohup", "man", "git", "tar", "cpio", "zip",
    "unzip", "gzip", "cp", "mv", "install", "tee", "chmod", "chown",
    "setfacl", "ln", "wget", "curl", "xargs", "expect", "script",
    "systemctl", "service", "useradd", "usermod", "passwd", "su",
}

# Kapabilitas yang langsung memberi jalur eskalasi. cap_net_raw/
# cap_net_bind_service sengaja TIDAK masuk (pengguna sah: ping dsb.)
# — dilaporkan filecap-unexpected (low) hanya di luar prefiks standar.
RISKY_CAPS = {
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_module", "cap_sys_ptrace", "cap_net_admin",
    "cap_mknod", "cap_bpf", "cap_setfcap", "cap_sys_boot",
    "cap_linux_immutable",
}

# Grup root-ekuivalen vs grup admin biasa.
ROOT_EQUIV_GROUPS = {"docker", "lxd"}
ADMIN_GROUPS = {"wheel", "sudo", "admin", "root", "adm", "staff"}

CAP_BIT_NAMES = {
    0: "cap_chown", 1: "cap_dac_override", 2: "cap_dac_read_search",
    3: "cap_fowner", 6: "cap_setgid", 7: "cap_setuid",
    10: "cap_net_bind_service", 12: "cap_net_admin", 13: "cap_net_raw",
    16: "cap_sys_module", 18: "cap_sys_chroot", 19: "cap_sys_ptrace",
    21: "cap_sys_admin", 27: "cap_mknod", 31: "cap_setfcap",
    33: "cap_mac_admin", 39: "cap_bpf",
}

SUID_MASK = 0o4000
SGID_MASK = 0o2000
STICKY_MASK = 0o1000
WORLD_WRITE = 0o002
GROUP_WRITE = 0o020

WALK_SKIP_NAMES = {"proc", "sys", "run", "dev"}
WALK_MAX_FILES = 2_000_000  # pengaman jarak; terpotong = temuan eksplisit

INCLUDE_KEYS = (("@includedir", "dir"), ("#includedir", "dir"),
                ("@include", "file"), ("#include", "file"))
_PAREN_RE = re.compile(r"\(([^)]*)\)")


def _add(findings: "list[dict]", fid: str, sev: str, msg: str,
         poc: str) -> None:
    findings.append({"id": fid, "severity": sev, "message": msg,
                     "poc": poc[:400]})


def _read_text(path: Path) -> "tuple[str | None, str]":
    """Teks file; (None, verdict) bila tak ada/tak terbaca."""
    try:
        if not path.is_file():
            return None, "absent"
        return path.read_text(encoding="utf-8", errors="replace"), "ok"
    except OSError:
        return None, "unreadable"


def _writable_no_sticky(mode: int) -> bool:
    return bool(mode & (WORLD_WRITE | GROUP_WRITE)) \
        and not (mode & STICKY_MASK)


def _is_world_writable(mode: int) -> bool:
    return bool(mode & WORLD_WRITE)


def _group_or_world_writable(mode: int) -> bool:
    return bool(mode & (WORLD_WRITE | GROUP_WRITE))


def _rel(root: Path, p: Path) -> str:
    try:
        return "/" + p.relative_to(root).as_posix()
    except ValueError:
        return str(p)


def _allowed(path: str, allow: "list[str]") -> bool:
    return any(path == a or path.startswith(a.rstrip("/") + "/")
               for a in allow)


# ---------------------------------------------------------------- sudoers

def _parse_cmnd_alias(line: str, aliases: "dict[str, list[str]]") -> None:
    parts = line.split("=", 1)
    if len(parts) != 2:
        return
    head = parts[0].split()
    if len(head) < 2:
        return
    members = [m.strip() for m in parts[1].split(",") if m.strip()]
    aliases.setdefault(head[1], []).extend(members)


def _parse_user_spec(line: str, source: str, lineno: int,
                     aliases: "dict[str, list[str]]",
                     findings: "list[dict]", stats: dict) -> None:
    try:
        m = _PAREN_RE.search(line)
        if m:
            user = line[:m.start()].split()[0]
            runas = m.group(1).strip()
            rest = line[m.end():].strip()
        elif "=" in line:
            lhs, rest = line.split("=", 1)
            toks = lhs.split()
            if len(toks) < 2:
                raise ValueError("spec pendek")
            user, runas = toks[0], ""  # token tengah = host, diabaikan
        else:
            raise ValueError("spec tanpa '='")
        if rest.upper().startswith("NOPASSWD:"):
            nopasswd, rest = True, rest[len("NOPASSWD:"):]
        elif rest.upper().startswith("PASSWD:"):
            nopasswd, rest = False, rest[len("PASSWD:"):]
        else:
            nopasswd = False
        # tag lain (SETENV:/NOEXEC:/LOG_INPUT: dst.) dibuang
        while rest and rest.split(":", 1)[0].strip().isupper() \
                and ":" in rest.split(",", 1)[0]:
            rest = rest.split(":", 1)[1]
        commands = [c.strip() for c in rest.split(",") if c.strip()]
        if not commands:
            raise ValueError("spec tanpa perintah")
    except ValueError:
        stats["sudoers_unparsed"] += 1
        return

    for cmd in commands:
        base = cmd.split()[0] if cmd.split() else cmd
        for member in aliases.get(base, [cmd]):
            toks = member.split()
            mbase = toks[0] if toks else member
            margs = toks[1:]
            stats["sudo_commands"] += 1
            poc = f"{source}:{lineno} {user} ({runas or '-'}) {member}"
            is_all = mbase.upper() == "ALL"
            wildcard = any("*" in t or "?" in t for t in margs)
            if not nopasswd:
                # ALL utk root / grup admin = praktik standar distro,
                # BUKAN temuan (anti-FP); user spesifik non-root = review
                if is_all and "all" in runas.lower() \
                        and user != "root" and not user.startswith("%"):
                    _add(findings, "sudo-runas-all", "medium",
                         f"{user} dapat menjalankan perintah apa pun "
                         f"(runas {runas}, tanpa NOPASSWD)", poc)
                continue
            name = Path(mbase).name.lower()
            if is_all:
                _add(findings, "sudo-nopasswd-all", "high",
                     f"{user}: NOPASSWD utk SEMUA perintah "
                     f"(runas {runas or '-'})", poc)
            elif name in RISKY_SUDO_COMMANDS:
                _add(findings, "sudo-nopasswd-risky", "high",
                     f"{user}: NOPASSWD '{mbase}' — memberi shell/"
                     f"penulisan berkas sbg {runas or 'root'}", poc)
            else:
                _add(findings, "sudo-nopasswd-other", "low",
                     f"{user}: NOPASSWD '{member}' (review)", poc)
            if wildcard:
                _add(findings, "sudo-wildcard-arg", "high",
                     f"{user}: spec '{member}' memuat wildcard — "
                     f"injeksi argumen sbg {runas or 'root'}", poc)


def _parse_sudoers_text(text: str, source: str,
                        aliases: "dict[str, list[str]]",
                        findings: "list[dict]",
                        stats: dict) -> "list[tuple[str, str]]":
    """Parse satu file sudoers; kembalikan (kind, arg) include-nya."""
    includes: "list[tuple[str, str]]" = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        matched_inc = False
        for key, kind in INCLUDE_KEYS:
            if low.startswith(key):
                arg = line[len(key):].strip()
                if arg:
                    includes.append((kind, arg))
                matched_inc = True
                break
        if matched_inc:
            continue
        words = line.split()
        first = words[0] if words else ""
        if first.lower() == "defaults":
            continue
        if first.startswith("#"):  # komentar
            continue
        if first.startswith("@"):  # @-directive lain
            continue
        if first.lower().startswith("cmnd_alias"):
            _parse_cmnd_alias(line, aliases)
            continue
        if first.isupper() and "=" in line:  # alias lain (tidak CMND)
            continue
        if first.startswith("%"):  # spesifikasi grup — tetap dievaluasi
            _parse_user_spec(line, source, lineno, aliases, findings,
                             stats)
            continue
        _parse_user_spec(line, source, lineno, aliases, findings, stats)
    return includes


def scan_sudoers(root: "Path | None", findings: "list[dict]",
                 stats: dict) -> None:
    stats["sudo_files"] = 0
    stats["sudoers_unparsed"] = 0
    stats["sudo_commands"] = 0
    if root is None:
        return
    aliases: "dict[str, list[str]]" = {}
    main = root / "etc" / "sudoers"
    text, verdict = _read_text(main)
    if text is None:
        stats["sudo_missing"] = True
        _add(findings, "sudoers-missing", "medium",
             f"sudoers {verdict} — cek sudo TIDAK terverifikasi "
             f"(collection-incomplete, fail-closed)", str(main))
        return
    stats["sudo_files"] += 1
    seen: "set[str]" = {str(main)}
    work: "list[tuple[str, str]]" = [(text, str(main))]
    while work:
        body, src = work.pop()
        for kind, arg in _parse_sudoers_text(body, src, aliases,
                                             findings, stats):
            # path include adalah path POSIX host; pada koleksi rootfs
            # dipetakan ke dalam salinan (absolute -> root/...,
            # relatif -> etc/) — cek slash, bukan Path.is_absolute()
            # (di Windows path tanpa drive dianggap relatif)
            if arg.startswith("/"):
                p = root / arg.lstrip("/")
            else:
                p = root / "etc" / arg
            if kind == "dir":
                if not p.is_dir():
                    continue
                cands = [f for f in sorted(p.iterdir())
                         if not f.name.endswith("~") and "." not in f.name]
            else:
                cands = [p]
            for f in cands:
                if str(f) in seen:
                    continue
                t, v = _read_text(f)
                if t is None:
                    continue
                seen.add(str(f))
                stats["sudo_files"] += 1
                work.append((t, str(f)))
    if stats["sudoers_unparsed"]:
        _add(findings, "sudoers-unparsed", "info",
             f"{stats['sudoers_unparsed']} baris spec sudoers tak "
             f"ter-parse — review manual", "sudoers")


# ---------------------------------------------------------------- passwd

PASSWD_SYSTEM_MAX_UID = 999


def scan_passwd(root: "Path | None", findings: "list[dict]",
                stats: dict) -> None:
    stats["passwd_users"] = 0
    stats["human_users"] = []
    if root is None:
        return
    text, verdict = _read_text(root / "etc" / "passwd")
    if text is None:
        stats["passwd_missing"] = True
        _add(findings, "passwd-missing", "info",
             f"/etc/passwd {verdict} — cek UID-0 tak terverifikasi",
             "etc/passwd")
        return
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split(":")
        if len(f) < 7:
            continue
        name = f[0]
        try:
            uid = int(f[2])
        except ValueError:
            continue
        stats["passwd_users"] += 1
        if uid == 0 and name != "root":
            _add(findings, "uid-0-account", "high",
                 f"akun '{name}' ber-UID 0 selain root (root "
                 f"ekuivalen, shell {f[6]})", f"etc/passwd:{line[:120]}")
        if uid > PASSWD_SYSTEM_MAX_UID:
            stats["human_users"].append(name)
    shadow, verdict = _read_text(root / "etc" / "shadow")
    if shadow is None:
        stats["shadow_absent"] = verdict
        return
    for line in shadow.splitlines():
        f = line.split(":")
        if len(f) < 2:
            continue
        if f[1] == "":
            _add(findings, "shadow-empty-password", "high",
                 f"akun '{f[0]}' TANPA password di /etc/shadow "
                 f"(login tanpa sandi)", f"etc/shadow:{f[0]}")


# ---------------------------------------------------------------- groups

def scan_groups(root: "Path | None", findings: "list[dict]",
                stats: dict) -> None:
    stats["risky_group_members"] = []
    if root is None:
        return
    text, verdict = _read_text(root / "etc" / "group")
    if text is None:
        stats["group_missing"] = True
        _add(findings, "group-missing", "info",
             f"/etc/group {verdict} — cek keanggotaan grup tak "
             f"terverifikasi", "etc/group")
        return
    humans = set(stats.get("human_users", []))
    for line in text.splitlines():
        f = line.split(":")
        if len(f) < 4 or not f[3]:
            continue
        gname = f[0]
        members = [m for m in f[3].split(",") if m]
        if gname in ROOT_EQUIV_GROUPS:
            for m in members:
                _add(findings, "risky-group-membership", "high",
                     f"'{m}' anggota grup '{gname}' (root-ekuivalen — "
                     f"mount/eksekusi container sbg root)",
                     f"etc/group:{line[:120]}")
                stats["risky_group_members"].append(f"{m}:{gname}")
        elif gname in ADMIN_GROUPS:
            for m in members:
                if m in humans:
                    _add(findings, "risky-group-membership", "medium",
                         f"'{m}' (human) anggota grup admin '{gname}' "
                         f"— review least-privilege",
                         f"etc/group:{line[:120]}")
                    stats["risky_group_members"].append(f"{m}:{gname}")


# ----------------------------------------------------- SUID/SGID & caps

def _check_priv_file(root: "Path | None", path: str, kind: str,
                     findings: "list[dict]", allow: "list[str]",
                     check_parents: bool) -> None:
    if _allowed(path, allow):
        return
    unexpected = not path.startswith(STANDARD_PREFIXES)
    if unexpected:
        _add(findings, f"{kind}-unexpected-location", "medium",
             f"{kind.upper()} berkas di luar prefiks standar: {path}",
             path)
    if root is not None:
        # berkas SUID/SGID itu sendiri world-writable = istilah root
        # (docstring: suid-writable-file / sgid-writable-file)
        try:
            fm = os.stat(root / path.lstrip("/")).st_mode
        except OSError:
            fm = None
        if fm is not None and statmod.S_ISREG(fm) and (fm & 0o0002):
            _add(findings, f"{kind}-writable-file", "high",
                 f"berkas {kind.upper()} itu sendiri world-writable: "
                 f"{path}", path)
    if check_parents and root is not None:
        parent_rel = os.path.dirname(path) or "/"
        real_parent = root / parent_rel.lstrip("/")
        try:
            pm = os.stat(real_parent).st_mode
        except OSError:
            pm = None
        if pm is not None and _writable_no_sticky(pm):
            _add(findings, f"{kind}-writable-dir",
                 "high" if kind == "suid" else "medium",
                 f"parent {kind.upper()} world/group-writable tanpa "
                 f"sticky: {parent_rel}", parent_rel)


def _report_caps(path: str, caps: "list[str]", findings: "list[dict]",
                 allow: "list[str]") -> None:
    if _allowed(path, allow):
        return
    risky = [c for c in caps if c in RISKY_CAPS]
    if risky:
        _add(findings, "filecap-risky", "high",
             f"{path}: capability berisiko {','.join(sorted(risky))}",
             path)
    elif not path.startswith(STANDARD_PREFIXES):
        _add(findings, "filecap-unexpected", "low",
             f"{path}: capability {','.join(sorted(caps))} di luar "
             f"prefiks standar", path)


def _decode_vfs_cap(blob: bytes) -> "list[str]":
    """security.capability xattr -> nama-nama cap (v1/v2/v3 LE)."""
    if len(blob) < 16:
        return []
    magic, revision, permitted, _inheritable = struct.unpack(
        "<IIII", blob[:16])
    if magic != 0x00000000 or revision not in (1, 2, 3):
        return []
    return [CAP_BIT_NAMES.get(i, f"cap_{i}")
            for i in range(41) if permitted & (1 << i)]


def scan_filemodes(root: "Path | None", findings: "list[dict]",
                   stats: dict, allow: "list[str]") -> None:
    """Walk rootfs: SUID/SGID, world-writable kritikal, xattr cap."""
    stats["files_scanned"] = 0
    stats["files_unreadable"] = 0
    stats["suid_found"] = 0
    stats["sgid_found"] = 0
    stats["xattr_cap_unreadable"] = 0
    if root is None:
        return
    root_s = str(root)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root_s).replace("\\", "/")
        first = rel_dir.split("/")[0] if rel_dir != "." else ""
        if first in WALK_SKIP_NAMES:
            dirnames[:] = []
            continue
        for name in filenames:
            fpath = os.path.join(dirpath, name)
            count += 1
            if count > WALK_MAX_FILES:
                stats["walk_truncated"] = True
                _add(findings, "collection-incomplete", "medium",
                     f"walk dihentikan di {count} berkas (batas jarak) — "
                     f"inventaris SUID TIDAK lengkap", root_s)
                return
            try:
                st = os.lstat(fpath)
            except OSError:
                stats["files_unreadable"] += 1
                continue
            mode = st.st_mode
            rel = _rel(root, Path(fpath))
            if _allowed(rel, allow):
                continue
            if mode & SUID_MASK:
                stats["suid_found"] += 1
                _check_priv_file(root, rel, "suid", findings, allow, True)
            if mode & SGID_MASK:
                stats["sgid_found"] += 1
                _check_priv_file(root, rel, "sgid", findings, allow, True)
            if _is_world_writable(mode) and statmod.S_ISREG(mode):
                if rel.startswith(("/etc/systemd/", "/lib/systemd/",
                                   "/usr/lib/systemd/", "/etc/init.d/")):
                    _add(findings, "worldwritable-unit", "high",
                         f"unit/init script world-writable: {rel}", rel)
                elif rel.startswith("/etc/"):
                    _add(findings, "worldwritable-etc", "medium",
                         f"berkas konfigurasi world-writable: {rel}", rel)
            try:
                if hasattr(os, "listxattr") and \
                        "security.capability" in os.listxattr(fpath):
                    blob = os.getxattr(fpath, "security.capability")
                    caps = _decode_vfs_cap(blob)
                    if caps:
                        _report_caps(rel, caps, findings, allow)
            except OSError:
                stats["xattr_cap_unreadable"] += 1
    stats["files_scanned"] = count


def scan_cap_list(path: "str | None", findings: "list[dict]",
                  stats: dict, allow: "list[str]") -> None:
    stats["cap_list_entries"] = 0
    if not path:
        return
    text, verdict = _read_text(Path(path))
    if text is None:
        raise ValueError(f"--cap-list {verdict}: {path}")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        if len(toks) < 2:
            continue
        fpath = toks[0]
        caps = [t.split("+")[0].split("=")[0].lower()
                for t in toks[1:] if t.lower().startswith("cap_")]
        if not caps:
            continue
        stats["cap_list_entries"] += 1
        _report_caps(fpath, caps, findings, allow)
    if not stats["cap_list_entries"]:
        raise ValueError(f"--cap-list tanpa entri dikenali: {path}")


def scan_suid_list(path: "str | None", root: "Path | None",
                   findings: "list[dict]", stats: dict,
                   allow: "list[str]") -> None:
    stats["suid_list_entries"] = 0
    if not path:
        return
    text, verdict = _read_text(Path(path))
    if text is None:
        raise ValueError(f"--suid-list {verdict}: {path}")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("/"):
            fpath, bits = line, ""
        else:
            toks = line.split()
            if len(toks) < 8 or not toks[0].startswith("-"):
                continue  # bukan baris `ls -l` berkas reguler
            bits, fpath = toks[0], toks[-1]
        stats["suid_list_entries"] += 1
        if not bits:
            # entri polos dari find -perm -4000 -o -perm -2000: tak bisa
            # dibedakan SUID vs SGID — perlakukan SUID (sisi lebih
            # berisiko), catat di stats
            stats["suid_list_ambiguous"] = \
                stats.get("suid_list_ambiguous", 0) + 1
            _check_priv_file(root, fpath, "suid", findings, allow,
                             root is not None)
        else:
            # ls -l: index 3 = posisi x user ('s' = setuid),
            #         index 6 = posisi x grup ('s' = setgid)
            if len(bits) >= 4 and bits[3] == "s":
                _check_priv_file(root, fpath, "suid", findings, allow,
                                 root is not None)
            if len(bits) >= 7 and bits[6] == "s":
                _check_priv_file(root, fpath, "sgid", findings, allow,
                                 root is not None)
    if not stats["suid_list_entries"]:
        raise ValueError(f"--suid-list tanpa entri dikenali: {path}")


# ----------------------------------------------------------------- NFS

def scan_exports(root: "Path | None", findings: "list[dict]",
                 stats: dict) -> None:
    stats["exports_entries"] = 0
    if root is None:
        return
    text, verdict = _read_text(root / "etc" / "exports")
    if text is None:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        stats["exports_entries"] += 1
        if "no_root_squash" in line:
            _add(findings, "nfs-no-root-squash", "high",
                 "export NFS no_root_squash — klien root = root di "
                 "server", f"etc/exports:{line[:120]}")
        else:
            toks = line.split()
            if len(toks) > 1 and toks[1].startswith("*"):
                _add(findings, "nfs-world-export", "medium",
                     "export NFS ke host '*' — review cakupan",
                     f"etc/exports:{line[:120]}")


# ---------------------------------------------------------------- cron

def _cron_commands(root: Path) -> "list[tuple[str, str]]":
    """[(sumber, perintah)] dari crontab + cron.d + spool."""
    out: "list[tuple[str, str]]" = []
    files: "list[Path]" = [root / "etc" / "crontab"]
    cron_d = root / "etc" / "cron.d"
    if cron_d.is_dir():
        files.extend(sorted(cron_d.iterdir()))
    spool = root / "var" / "spool" / "cron"
    if spool.is_dir():
        files.extend(f for f in spool.rglob("*") if f.is_file())
    for f in files:
        text, _v = _read_text(f)
        if text is None:
            continue
        user_crontab = "spool" in str(f)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "@")):
                continue
            head = line.split(None, 1)[0]
            if "=" in head:  # PATH=/SHELL=/MAILTO=
                continue
            toks = line.split(None, 6)
            if user_crontab:
                if len(toks) >= 6:
                    out.append((str(f), toks[5]))
            elif len(toks) >= 7:
                out.append((str(f), toks[6]))
    return out


def scan_cron(root: "Path | None", findings: "list[dict]",
              stats: dict) -> None:
    stats["cron_entries"] = 0
    if root is None:
        return
    for src, cmd in _cron_commands(root):
        stats["cron_entries"] += 1
        if "*" in cmd:
            _add(findings, "cron-wildcard-args", "medium",
                 f"perintah cron memuat wildcard telanjang (injeksi "
                 f"argumen ala tar/find): {cmd[:120]}",
                 f"{src}:{cmd[:120]}")
        for tok in cmd.split():
            if not tok.startswith("/"):
                continue
            tok_clean = tok.strip("'\"")
            target = root / tok_clean.lstrip("/")
            try:
                tmode = os.lstat(target).st_mode
            except OSError:
                continue
            if statmod.S_ISREG(tmode) and _writable_no_sticky(tmode):
                _add(findings, "cron-writable-target", "high",
                     f"perintah cron mengeksekusi berkas writable: "
                     f"{tok_clean}", f"{src}:{cmd[:120]}")
                break


# ---------------------------------------------------------------- PATH

def scan_path_dirs(root: "Path | None", findings: "list[dict]",
                   stats: dict) -> None:
    stats["path_dirs_checked"] = 0
    if root is None:
        return
    sources = [root / "etc" / "profile", root / "etc" / "environment"]
    pd = root / "etc" / "profile.d"
    if pd.is_dir():
        sources.extend(sorted(pd.glob("*.sh")))
    seen: "set[str]" = set()
    for f in sources:
        text, _v = _read_text(f)
        if text is None:
            continue
        for line in text.splitlines():
            if "PATH" not in line or "=" not in line:
                continue
            val = line.split("=", 1)[1].strip().strip('"').strip("'")
            if "$" in val:
                continue  # nilai dinamis, tak bisa dinilai statis
            for d in val.split(":"):
                d = d.strip()
                if not d.startswith("/") or d in seen:
                    continue
                seen.add(d)
                stats["path_dirs_checked"] += 1
                dp = root / d.lstrip("/")
                try:
                    dmode = os.stat(dp).st_mode
                except OSError:
                    continue
                if _group_or_world_writable(dmode):
                    _add(findings, "path-dir-writable", "medium",
                         f"PATH directory group/world-writable: {d} "
                         f"(sumber {f.name})", str(f))


# ---------------------------------------------------------------- main

def _parse_args(argv: "list[str] | None") -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Audit offline vektor privesc Linux dari rootfs/list")
    ap.add_argument("--root", help="direktori rootfs salinan/koleksi")
    ap.add_argument("--suid-list", help="stdout 'find / -perm -4000 -o "
                    "-perm -2000 -type f' (atau ls -l)")
    ap.add_argument("--cap-list", help="stdout 'getcap -r /'")
    ap.add_argument("--allow-path", action="append", default=[],
                    help="path pengecualian (dicatat, bukan silent)")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), default="medium")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    root = Path(args.root) if args.root else None
    if root is not None and not root.is_dir():
        print(json.dumps({"schema": SCHEMA,
                          "error": f"--root bukan direktori: {args.root}"}),
              file=sys.stderr)
        return 2
    if root is None and not args.suid_list and not args.cap_list:
        print(json.dumps({"schema": SCHEMA,
                          "error": "butuh --root dan/atau --suid-list/"
                                   "--cap-list"}), file=sys.stderr)
        return 2

    findings: "list[dict]" = []
    notes: "list[str]" = []
    stats: dict = {"human_users": []}
    allow = [a for a in args.allow_path if a]

    try:
        scan_sudoers(root, findings, stats)
        scan_passwd(root, findings, stats)
        scan_groups(root, findings, stats)
        scan_filemodes(root, findings, stats, allow)
        scan_cap_list(args.cap_list, findings, stats, allow)
        scan_suid_list(args.suid_list, root, findings, stats, allow)
        scan_exports(root, findings, stats)
        scan_cron(root, findings, stats)
        scan_path_dirs(root, findings, stats)
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    if stats.get("xattr_cap_unreadable"):
        notes.append(f"{stats['xattr_cap_unreadable']} xattr "
                     "security.capability tak terbaca — cek capability "
                     "parsial (koleksi mungkin tanpa --xattrs)")
    if root is None:
        notes.append("tanpa --root: hanya cek berbasis daftar; cek "
                     "sudoers/passwd/group/cron/PATH tidak dijalankan")
    if stats.get("suid_list_ambiguous"):
        notes.append(f"{stats['suid_list_ambiguous']} entri --suid-list "
                     "tanpa mode — dihitung sbg SUID (sisi lebih berisiko)")
    if stats.get("walk_truncated"):
        notes.append("walk rootfs terpotong pada batas jarak — "
                     "inventaris SUID/SGID parsial")

    seen: "set[tuple]" = set()
    uniq: "list[dict]" = []
    for f in findings:
        key = (f["id"], f["poc"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    findings = uniq
    findings.sort(key=lambda f: -SEV_ORDER.get(f["severity"], 0))

    threshold = SEV_ORDER[args.fail_on]
    worst = max((SEV_ORDER.get(f["severity"], 0) for f in findings),
                default=0)
    result = {
        "schema": SCHEMA,
        "stats": stats,
        "fail_on": args.fail_on,
        "findings": findings,
        "notes": notes,
        "verdict": "findings" if worst >= threshold else "clean",
    }
    out_text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(out_text, encoding="utf-8")
    print(out_text)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
