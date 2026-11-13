r"""[SAFETY: read-only] linux_persist_scan — audit OFFLINE lokasi
persistensi Linux dari koleksi rootfs (salinan forensik/arsip tar):
cron, unit systemd, rc.local, authorized_keys, ld.so.preload,
modules-load, hook PAM, skrip shell profile. TANPA jaringan.

Pembagian ranah (TIDAK diduplikasi):
  - persistensi WINDOWS (Run key, service, task, WMI, startup, COM)
    -> win_persist_triage
  - log eksekusi CRON/sudo yang SUDAH jalan -> linux_auth_triage
  - lolbin Windows -> lolbin_scan
  - di sini: file konfigurasi persistensi Linux terkumpul.

Input -> mekanisme -> output:
  - Input : --root DIR = direktori rootfs koleksi (struktur /etc,
            /var/spool, /home, /root, /usr seperti host asal; boleh
            subset). Baca-saja, NOL jaringan.
  - Mekanisme: parse tiap lokasi persistensi dgn parser minimalis
            (crontab 6/7 kolom + @reboot, INI unit systemd, format
            authorized_keys option-keytype-base64-comment) dan tandai
            pola: curl/wget ke URL, base64/openssl-enc/-c python,
            path /tmp //var/tmp //dev/shm, pam_exec/pam_script,
            entri ld.so.preload, opsi command= pada authorized_keys,
            tipe kunci ssh-dss.
  - Output: JSON {schema, stats, findings, notes}; finding =
            {check, severity, path, line, message}.

Cek:
  cron-downloader        (high): entri cron memanggil curl/wget ke URL.
  unit-downloader        (high): ExecStart* unit systemd memanggil
                         curl/wget ke URL.
  cron-encoded-cmd       (medium): base64 -d / openssl enc / python -c.
  unit-encoded-cmd       (medium): idem di unit systemd.
  cron-tmp-path          (medium): perintah merujuk /tmp//var/tmp/
                         /dev/shm.
  unit-tmp-path          (medium): idem di unit systemd.
  rc-local-downloader/-encoded-cmd/-tmp-path : pola sama pada
                         /etc/rc.local (high/medium/medium).
  profile-downloader/-encoded-cmd/-tmp-path  : pola sama pada skrip
                         shell (profile.d, /root/.bashrc, /root/.profile,
                         /etc/bash.bashrc, /etc/profile).
  authkey-forced-command (medium): authorized_keys dengan opsi
                         command="..." (shell paksa saat kunci dipakai).
  authkey-weak-type      (medium): kunci ssh-dss (DSA usang).
  authkey-unparsed       (high): baris authorized_keys tak bisa
                         diekstrak (fail-closed).
  ld-preload-entry       (high): /etc/ld.so.preload berisi entri —
                         vektor rootkit klasik, jarang sah.
  pam-exec-hook          (medium): pam_exec.so / pam_script.so di
                         /etc/pam.d/*.
  module-load-entry      (info): modul kustom via modules-load.d/*.conf
                         atau /etc/modules.
  cron-reboot-entry      (info): entri @reboot — sah tapi layak baseline.
  file-unreadable        (medium): file lokasi tidak bisa dibaca —
                         tidak pernah dianggap bersih.
  collection-incomplete  (medium): TIDAK ADA lokasi persistensi yang
                         ditemukan di root — koleksi kurang (fail-closed,
                         bukan bersih).

Fail-closed:
  - --root tidak ada / bukan direktori -> exit 2.
  - tidak ada satu lokasi pun ditemukan -> collection-incomplete.
  - baris authorized_keys tak ter-parse -> authkey-unparsed.
  - file tidak terbaca -> file-unreadable.

Anti-FP: hanya baris non-komentar yang dievaluasi; downloader WAJIB
berpasangan token curl/wget + skema URL; --allow-path PREFIX (boleh
diulang) menyaring path sah (unit vendor) — jumlah saringan dicatat.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error input.

Pemakaian:
  python tools/linux_persist_scan.py --root /cases/host-rootfs \
      --out persist.json
  python tools/linux_persist_scan.py --root rootfs \
      --allow-path /etc/systemd/system/multi-user.target.wants
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.linux-persist-scan/1"
MAX_FILE_BYTES = 8 * 1024 * 1024

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

RE_URL = re.compile(r"(?:https?|ftp)://", re.IGNORECASE)
RE_DOWNLOADER = re.compile(r"\b(?:curl|wget|fetch|lwp-download)\b",
                           re.IGNORECASE)
RE_ENCODED = re.compile(
    r"(?:base64\s+(?:-d|--decode|-D)|openssl\s+enc\b|"
    r"(?:python3?|perl|php)\s+(?:-(?:c|e)\b|--eval\b))", re.IGNORECASE)
RE_TMP_PATH = re.compile(r"(?:^|[\s'\"=])/(?:tmp|var/tmp|dev/shm)/",
                         re.IGNORECASE)

# (crontab /etc & cron.d = 6 kolom + user; spool user = 5 kolom)
RE_TIME_FIELD = re.compile(r"^(?:[@\w,*\-/]+)(?:\s+[\w,*\-/]+){0,5}$")
KEY_TYPES = {"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256",
             "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-dss"}

CRON_DIRS = ("etc/cron.d", "var/spool/cron/crontabs", "var/spool/cron")
CRON_FILES = ("etc/crontab",)
UNIT_DIRS = ("etc/systemd/system", "usr/lib/systemd/system")
RC_LOCAL = "etc/rc.local"
PROFILE_FILES = ("root/.bashrc", "root/.profile", "etc/bash.bashrc",
                 "etc/profile")
MODULE_FILES = ("etc/modules",)


def _read(root: Path, rel: str) -> "tuple[str, str] | None":
    """Baca file koleksi; kembalikan (text, err) atau None bila absen."""
    p = root / rel
    if not p.exists():
        return None
    try:
        if p.is_dir():
            return None
        if p.stat().st_size > MAX_FILE_BYTES:
            return "", f"file terlalu besar: {rel}"
        return p.read_text(encoding="utf-8", errors="replace"), ""
    except OSError as exc:
        return "", str(exc)


def _is_comment(line: str) -> bool:
    return (not line.strip()) or line.strip().startswith("#")


def _cmd_flags(cmd: str) -> "list[str]":
    """Klasifikasi perintah shell -> daftar flag pola."""
    flags = []
    if RE_DOWNLOADER.search(cmd) and RE_URL.search(cmd):
        flags.append("downloader")
    if RE_ENCODED.search(cmd):
        flags.append("encoded")
    if RE_TMP_PATH.search(cmd):
        flags.append("tmp-path")
    return flags


FLAG_CHECKS = {
    "downloader": ("downloader", "high"),
    "encoded": ("encoded-cmd", "medium"),
    "tmp-path": ("tmp-path", "medium"),
}


def _flag_findings(check_prefix: str, flags: "list[str]", path: str,
                   line_no: int, cmd: str, out: "list[dict]") -> None:
    for fl in flags:
        kind, sev = FLAG_CHECKS[fl]
        msg = {
            "downloader": f"{check_prefix} memanggil downloader ke URL — "
                          "pola drop/pull payload; verifikasi tujuan.",
            "encoded": f"{check_prefix} mengeksekusi payload "
                       "ter-encode (base64/openssl/-c) — "
                       "menyembunyikan perintah adalah pola "
                       "persistensi.",
            "tmp-path": f"{check_prefix} merujuk path tmp/dev-shm — "
                        "staging umum payload.",
        }[fl]
        out.append({
            "check": f"{check_prefix}-{kind}",
            "severity": sev, "path": path, "line": line_no,
            "message": f"{msg} [perintah: {cmd[:120]}]",
        })


class _PersistScan:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.findings: "list[dict]" = []
        self.stats: "dict" = {"files_scanned": 0, "files_unreadable": 0,
                              "cron_entries": 0, "unit_files": 0,
                              "authkey_lines": 0, "locations_found": 0,
                              "allowed_filtered": 0}

    def unreadable(self, path: str, err: str) -> None:
        self.stats["files_unreadable"] += 1
        self.findings.append({
            "check": "file-unreadable", "severity": "medium",
            "path": path, "line": 0,
            "message": f"file tidak bisa dibaca ({err}) — tidak pernah "
                       "dianggap bersih.",
        })

    # ---- cron -------------------------------------------------------
    def scan_cron(self) -> None:
        found_any = False
        targets: "list[tuple[str, str]]" = []
        for rel in CRON_FILES:
            targets.append((rel, "system"))
        for d in CRON_DIRS:
            p = self.root / d
            if p.is_dir():
                for f in sorted(p.iterdir()):
                    if f.is_file():
                        rel = f.relative_to(self.root).as_posix()
                        targets.append((rel, "spool"
                                        if "spool" in d else "system"))
        for rel, style in targets:
            got = _read(self.root, rel)
            if got is None:
                continue
            found_any = True
            text, err = got
            if err:
                self.unreadable(rel, err)
                continue
            self.stats["files_scanned"] += 1
            for i, raw in enumerate(text.splitlines(), 1):
                if _is_comment(raw):
                    continue
                s = raw.strip()
                if re.match(r"^[A-Z_]+=", s):  # SHELL=/PATH env
                    continue
                toks = s.split(None, 6)
                if s.startswith("@"):
                    if s.lower().startswith("@reboot"):
                        self.stats["cron_entries"] += 1
                        self.findings.append({
                            "check": "cron-reboot-entry", "severity": "info",
                            "path": rel, "line": i,
                            "message": f"entri @reboot: {s[:120]} — sah "
                                       "tapi layak ada di baseline.",
                        })
                    continue
                if len(toks) < 6:
                    continue  # baris lanjutan/korup — bukan entry cron
                self.stats["cron_entries"] += 1
                # system (/etc/crontab, cron.d): 5 kolom waktu + user + cmd
                # spool (user crontab): 5 kolom waktu + cmd
                if style == "system" and len(toks) >= 7:
                    cmd = toks[6]
                else:
                    cmd = toks[5]
                flags = _cmd_flags(s)
                if flags:
                    _flag_findings("cron", flags, rel, i, cmd,
                                   self.findings)
        if found_any:
            self.stats["locations_found"] += 1

    # ---- systemd ----------------------------------------------------
    def scan_units(self) -> None:
        found_any = False
        for d in UNIT_DIRS:
            p = self.root / d
            if not p.is_dir():
                continue
            for f in sorted(p.rglob("*.service")):
                if not f.is_file():
                    continue
                rel = f.relative_to(self.root).as_posix()
                got = _read(self.root, rel)
                if got is None:
                    continue
                found_any = True
                text, err = got
                if err:
                    self.unreadable(rel, err)
                    continue
                self.stats["files_scanned"] += 1
                self.stats["unit_files"] += 1
                section = ""
                for i, raw in enumerate(text.splitlines(), 1):
                    line = raw.strip()
                    if _is_comment(line):
                        continue
                    if line.startswith("[") and line.endswith("]"):
                        section = line[1:-1].lower()
                        continue
                    if section != "service" or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    if key.strip().lower() not in (
                            "execstart", "execstartpre", "execstartpost",
                            "execreload"):
                        continue
                    cmd = val.strip()
                    flags = _cmd_flags(cmd)
                    if flags:
                        _flag_findings("unit", flags, rel, i, cmd,
                                       self.findings)
        if found_any:
            self.stats["locations_found"] += 1

    # ---- rc.local ----------------------------------------------------
    def scan_rc_local(self) -> None:
        got = _read(self.root, RC_LOCAL)
        if got is None:
            return
        self.stats["locations_found"] += 1
        text, err = got
        if err:
            self.unreadable(RC_LOCAL, err)
            return
        self.stats["files_scanned"] += 1
        for i, raw in enumerate(text.splitlines(), 1):
            if _is_comment(raw):
                continue
            flags = _cmd_flags(raw.strip())
            if flags:
                _flag_findings("rc-local", flags, RC_LOCAL, i,
                               raw.strip(), self.findings)

    # ---- authorized_keys ---------------------------------------------
    def scan_authkeys(self) -> None:
        found_any = False
        cands: "list[str]" = []
        for d in ("root/.ssh", "home"):
            p = self.root / d
            if not p.is_dir():
                continue
            if d == "root/.ssh":
                cands.append("root/.ssh/authorized_keys")
                continue
            for f in sorted(p.rglob("authorized_keys")):
                if f.is_file():
                    cands.append(f.relative_to(self.root).as_posix())
        for rel in cands:
            got = _read(self.root, rel)
            if got is None:
                continue
            found_any = True
            text, err = got
            if err:
                self.unreadable(rel, err)
                continue
            self.stats["files_scanned"] += 1
            for i, raw in enumerate(text.splitlines(), 1):
                line = raw.strip()
                if _is_comment(line):
                    continue
                toks = line.split()
                # token TIPE KUNCI menandai batas: sebelum = options
                # (bisa multi-token karena spasi dalam kutip), sesudah
                # = blob + komentar
                ki = next((j for j, t in enumerate(toks)
                           if t in KEY_TYPES), None)
                if ki is None:
                    self.findings.append({
                        "check": "authkey-unparsed", "severity": "high",
                        "path": rel, "line": i,
                        "message": "baris authorized_keys tak bisa "
                                   "diekstrak tipe kuncinya (fail-closed) "
                                   "— cek format/korupsi.",
                    })
                    continue
                self.stats["authkey_lines"] += 1
                opts = toks[:ki]
                if any(o.lower().startswith("command=")
                       for o in opts):
                    self.findings.append({
                        "check": "authkey-forced-command",
                        "severity": "medium", "path": rel, "line": i,
                        "message": "kunci dengan opsi command= — "
                                   "shell PAKSA saat kunci dipakai; "
                                   "verifikasi perintahnya.",
                    })
                if toks[ki] == "ssh-dss":
                    self.findings.append({
                        "check": "authkey-weak-type", "severity":
                            "medium", "path": rel, "line": i,
                        "message": "kunci ssh-dss (DSA) usang — "
                                   "migrasi ke ed25519/rsa>=3072.",
                    })
        if found_any:
            self.stats["locations_found"] += 1

    # ---- ld.so.preload ------------------------------------------------
    def scan_ld_preload(self) -> None:
        got = _read(self.root, "etc/ld.so.preload")
        if got is None:
            return
        self.stats["locations_found"] += 1
        text, err = got
        if err:
            self.unreadable("etc/ld.so.preload", err)
            return
        self.stats["files_scanned"] += 1
        for i, raw in enumerate(text.splitlines(), 1):
            if _is_comment(raw):
                continue
            self.findings.append({
                "check": "ld-preload-entry", "severity": "high",
                "path": "etc/ld.so.preload", "line": i,
                "message": f"/etc/ld.so.preload berisi '{raw.strip()[:80]}' "
                           "— vektor rootkit klasik; jarang ada yang sah, "
                           "verifikasi asal library.",
            })

    # ---- modules -------------------------------------------------------
    def scan_modules(self) -> None:
        found_any = False
        targets: "list[str]" = list(MODULE_FILES)
        p = self.root / "etc/modules-load.d"
        if p.is_dir():
            targets.extend(f.relative_to(self.root).as_posix()
                           for f in sorted(p.iterdir()) if f.is_file())
        for rel in targets:
            got = _read(self.root, rel)
            if got is None:
                continue
            found_any = True
            text, err = got
            if err:
                self.unreadable(rel, err)
                continue
            self.stats["files_scanned"] += 1
            for i, raw in enumerate(text.splitlines(), 1):
                if _is_comment(raw) or not raw.strip():
                    continue
                self.findings.append({
                    "check": "module-load-entry", "severity": "info",
                    "path": rel, "line": i,
                    "message": f"modul kustom '{raw.strip()[:60]}' "
                               "dimuat saat boot — baseline-kan.",
                })
        if found_any:
            self.stats["locations_found"] += 1

    # ---- PAM ------------------------------------------------------------
    def scan_pam(self) -> None:
        p = self.root / "etc/pam.d"
        if not p.is_dir():
            return
        found_any = False
        for f in sorted(p.iterdir()):
            if not f.is_file():
                continue
            rel = f.relative_to(self.root).as_posix()
            got = _read(self.root, rel)
            if got is None:
                continue
            found_any = True
            text, err = got
            if err:
                self.unreadable(rel, err)
                continue
            self.stats["files_scanned"] += 1
            for i, raw in enumerate(text.splitlines(), 1):
                if _is_comment(raw):
                    continue
                low = raw.lower()
                if "pam_exec.so" in low or "pam_script" in low:
                    self.findings.append({
                        "check": "pam-exec-hook", "severity": "medium",
                        "path": rel, "line": i,
                        "message": "hook pam_exec/pam_script di konfigurasi "
                                   f"PAM: {raw.strip()[:110]} — kode "
                                   "jalan saat autentikasi; verifikasi.",
                    })
        if found_any:
            self.stats["locations_found"] += 1

    # ---- shell profile ---------------------------------------------------
    def scan_profiles(self) -> None:
        found_any = False
        targets: "list[str]" = list(PROFILE_FILES)
        p = self.root / "etc/profile.d"
        if p.is_dir():
            targets.extend(f.relative_to(self.root).as_posix()
                           for f in sorted(p.iterdir()) if f.is_file())
        for rel in targets:
            got = _read(self.root, rel)
            if got is None:
                continue
            found_any = True
            text, err = got
            if err:
                self.unreadable(rel, err)
                continue
            self.stats["files_scanned"] += 1
            for i, raw in enumerate(text.splitlines(), 1):
                if _is_comment(raw):
                    continue
                flags = _cmd_flags(raw.strip())
                if flags:
                    _flag_findings("profile", flags, rel, i,
                                   raw.strip(), self.findings)
        if found_any:
            self.stats["locations_found"] += 1


def scan(root_dir: Path) -> "tuple[list[dict], dict]":
    sc = _PersistScan(root_dir)
    sc.scan_cron()
    sc.scan_units()
    sc.scan_rc_local()
    sc.scan_authkeys()
    sc.scan_ld_preload()
    sc.scan_modules()
    sc.scan_pam()
    sc.scan_profiles()
    if sc.stats["locations_found"] == 0:
        sc.findings.append({
            "check": "collection-incomplete", "severity": "medium",
            "path": str(root_dir), "line": 0,
            "message": "TIDAK ada lokasi persistensi (cron/systemd/rc."
                       "local/authorized_keys/ld.so.preload/pam.d/"
                       "profile) ditemukan di root koleksi — koleksi "
                       "kurang; hasil TIDAK boleh dibaca 'bersih'.",
        })
    return sc.findings, sc.stats


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit lokasi persistensi Linux dari koleksi rootfs, "
                    "nol jaringan.")
    ap.add_argument("--root", required=True,
                    help="direktori rootfs koleksi forensik")
    ap.add_argument("--allow-path", action="append", default=[],
                    metavar="PREFIX",
                    help="abaikan temuan pada path-prefix ini (bisa "
                         "diulang); dicatat di stats")
    ap.add_argument("--fail-on", default="medium",
                    choices=["info", "low", "medium", "high", "critical"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(json.dumps({
            "schema": SCHEMA,
            "error": f"root koleksi tidak ada/bukan direktori: {root}",
        }), file=sys.stderr)
        return 2

    findings, stats = scan(root)

    allow = tuple(a.strip().rstrip("/") for a in args.allow_path
                  if a.strip())
    if allow:
        kept = []
        for f in findings:
            fp = str(f["path"]).rstrip("/")
            if any(fp == a or fp.startswith(a + "/") for a in allow):
                stats["allowed_filtered"] = \
                    stats.get("allowed_filtered", 0) + 1
                continue
            kept.append(f)
        findings = kept

    threshold = SEV_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEV_ORDER.get(f["severity"], 0) >= threshold]

    notes = [
        "audit STATIS koleksi rootfs — jalankan di salinan (tar/image), "
        "bukan di host hidup; host hidup butuh alat respon insiden lain.",
        "sisi Windows ranah win_persist_triage; log eksekusi yang SUDAH "
        "jalan (CRON/sudo) ranah linux_auth_triage.",
        "in-memory only (tanpa jejak disk) TIDAK tercakup — butuh "
        "memori dump (cf. METHODS seksi memori-forensik).",
        "koleksi tanpa lokasi persistensi dilaporkan eksplisit "
        "(collection-incomplete), tidak pernah dibaca bersih.",
    ]
    if stats.get("allowed_filtered"):
        notes.append(f"{stats['allowed_filtered']} temuan disaring via "
                     "--allow-path — saringan dicatat, tidak dipendam.")

    report = {
        "schema": SCHEMA,
        "stats": stats,
        "findings": sorted(
            findings,
            key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                           f["check"], f["path"], f["line"])),
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
