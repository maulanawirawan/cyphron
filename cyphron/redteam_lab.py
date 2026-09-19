"""redteam_lab — Katalog tradecraft lab + simulasi berotorisasi (U9 full).

Semua di sini berjalan HANYA di lab milik sendiri / lingkungan engagement
BEROTORISASI eksplisit. Pagar tanpa kompromi:

- C2-SIMULATION: beacon simulasi HANYA loopback (127.0.0.1), berbatas
  (jumlah beacon + durasi), TANPA persistensi ke disk, TANPA payload ofensif.
  Tujuannya validasi protokol + alat + unit-test rule deteksi — bukan
  infrastruktur serangan.
- PRIVESC READ-ONLY: pemindaian kesalahan konfigurasi host LAB yang bisa
  dipakai privesc (PATH writable, world-writable, SUID) — baca saja,
  tidak ada upaya eskalasi nyata.
- PERSISTENCE/LATERAL/EVASION MATRIX: katalog + peta cakupan deteksi
  (purple-team) — perencanaan engagement, bukan eksekusi.

Sumber kebenaran: katalog tradecraft RTL-* dengan requirement otorisasi
eksplisit per teknik. Setiap teknik menyertakan telemetri yang HARUS
dikumpulkan tim biru (nilai jual: deteksi-hint, bukan senjata).
"""

from __future__ import annotations

import json
import os
import socket
import stat
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ------------------------------------------------------- katalog tradecraft
AUTH_LAB = "lab"          # boleh di lab milik sendiri
AUTH_ENGAGE = "engagement"  # butuh dokumen otorisasi engagement


@dataclass
class Technique:
    tid: str
    phase: str
    name: str
    auth: str                    # AUTH_LAB | AUTH_ENGAGE
    lab_setup: str
    simulation: str              # outline — bukan payload
    telemetry: list[str]         # yang WAJIB dikumpulkan tim biru
    purple_note: str


TRADECRAFT: list[Technique] = [
    Technique(
        "RTL-01", "INITIAL_ACCESS", "Phishing simulasi (lab mail-server)",
        AUTH_LAB,
        "mail-server lokal + domain lab (.lab TLD) + kotak korban uji",
        "kirim email uji ber-lampiran bening + halaman kredensial lab; kredensial "
        "uji disetel agar alarm; TIDAK menyentuh korban nyata",
        ["gateway log (SPF/DMARC verdict)", "mail box delivery",
         "klik/link telemetry lab"],
        "Uji rule: ekstensi lampiran + domain baru terdaftar <7 hari = score naik"),
    Technique(
        "RTL-02", "EXECUTION", "Loader chain decode (marker-driven)",
        AUTH_LAB,
        "fixture blob terobfuskasi milik sendiri (chain_decoder)",
        "dekodi rantai b64/rc4/xor di sandbox, marker unik per tahap; tanpa "
        "payload nyata",
        ["proses child yang lahir", "fileless write ke memori (ETW/eBPF lab)",
         "amssolver/dumper log"],
        "Marker aritmetika ter-refleksi = cara aman membuktikan eksekusi tanpa "
        "menjalankan muatan"),
    Technique(
        "RTL-03", "PERSISTENCE", "Persistence matrix (checkpoint saja)",
        AUTH_ENGAGE,
        "VM lab snapshot bersih (satu teknik per snapshot)",
        "daftar lokasi persistence (autorun, service, cron, WMI/subscriber) — "
        "dijalankan SATU per SATU di snapshot, dicabut + diverifikasi kembali "
        "bersih setiap selesai",
        ["registry/run-key diff", "unit/systemd/cron diff", "service creation "
         "event (7045)", "startup folder listing"],
        "Laporan wajib menyertakan bukti rollback (diff sebelum/sesudah kosong)"),
    Technique(
        "RTL-04", "PRIV_ESC", "Privesc playbook read-only",
        AUTH_ENGAGE,
        "host lab / target engagement berotorisasi",
        "pemindaian read-only: PATH writable, world-writable, SUID, service "
        "misconfig (lihat privesc_scan) — TIDAK ADA upaya eskalasi nyata "
        "tanpa persetujuan tertulis terpisah",
        ["filesystem ACL snapshot", "service config dump", "sudoers/registry "
         "audit (read-only)"],
        "Temuan misconfig = temuan klien (L3 jika terbukti dengan objek "
        "spesifik); upaya eksploitasi = tahap terpisah berotorisasi"),
    Technique(
        "RTL-05", "DEFENSE_EVASION", "Evasion assessment (telemetry-first)",
        AUTH_ENGAGE,
        "EDR/AV lab + telemetri yang bisa diperiksa",
        "variasikan teknik yang SUDAH di-allowlist lab (ganti nama proses, "
        "delay, encode) lalu ukur: apakah telemetri tetap tertangkap? "
        "TANPA menyerang proteksi orang lain",
        ["EDR event per variasi", "AV verdict", "alert latency"],
        "Keluaran = coverage report (teknik terdeteksi / tidak), bukan bypass kit"),
    Technique(
        "RTL-06", "CRED_ACCESS", "Credential exposure sweep (lab vault)",
        AUTH_LAB,
        "vault lab berisi kredensial kejakan + decoy",
        "sweep file/config/registry lab utk pola kredensial; decoy wajib "
        "tertangkap = alat valid",
        ["file access audit", "vault access log", "memory string scan lab"],
        "Zero-FP: kredensial ter-decode wajib printable + pemisah ':' (lesson "
        "'Basic protection')"),
    Technique(
        "RTL-07", "DISCOVERY", "Discovery sweep terukur",
        AUTH_ENGAGE,
        "lab domain dengan inventaris dikenal",
        "jalankan urutan discovery (net/user/share) dengan pacing tetap; "
        "bandingkan inventaris vs hasil = recall alat",
        ["log query AD/LDAP", "network sweep telemetry", "endpoint audit log"],
        "Inventaris dikenal = ground truth; hasil discovery dibandingkan 1:1"),
    Technique(
        "RTL-08", "LATERAL", "Lateral-movement simulation (path saja)",
        AUTH_ENGAGE,
        "dua host lab, akun uji, share uji",
        "simulasi: validasi kredensial lintas host + listing share — TANPA "
        "eksekusi remote payload; jalur dicatat sebagai path",
        ["auth event (4624 type 3)", "share access log", "network flow antar-host"],
        "Lateral path = graf; laporan menyertakan path + kontrol yang seharusnya "
        "memutusnya"),
    Technique(
        "RTL-09", "C2", "C2-simulation loopback (protokol + deteksi)",
        AUTH_LAB,
        "listener loopback 127.0.0.1 + beacon thread lab",
        "beacon simulasi: HELLO -> task -> ACK dengan jitter interval, berbatas "
        "jumlah dan durasi; protokol polos ter-log (bukan stealth) supaya rule "
        "deteksi bisa diuji",
        ["loopback flow (pcap lab)", "proses beacon", "log listener"],
        "Sim loopback TIDAK mengukur deteksi jaringan nyata (tidak keluar NIC) — "
        "fungsinya validasi protokol alat + unit-test rule"),
    Technique(
        "RTL-10", "EXFIL", "Exfil canary (marker-driven)",
        AUTH_ENGAGE,
        "kanal lab + file canary milik sendiri",
        "transfer file canary ber-marker melalui kanal yang DIIZINKAN dokumen; "
        "ukur: alarm DLP/egress tertangkap atau tidak",
        ["egress log", "DLP alert", "DNS query log (untuk DNS-canal test lab)"],
        "Canary unik = bukti deterministik (L3) bila sampai di sisi penerima"),
    Technique(
        "RTL-11", "IMPACT", "Ransomware-simulation dry-run (mati sebelum aksi)",
        AUTH_ENGAGE,
        "VM lab snapshot; drive uji berisi file canary",
        "simulasi ALUR saja: temukan file -> hitung canary -> STOP sebelum "
        "encryption; kemudian uji restore playbook",
        ["file access burst telemetry", "backup job log", "restore test hasil"],
        "Tidak pernah mengenkripsi file nyata; nilai = bukti deteksi burst + "
        "kecepatan restore"),
    Technique(
        "RTL-12", "RECON", "Recon pasif externa terdokumentasi",
        AUTH_ENGAGE,
        "sumber publik; tanpa interaksi infra",
        "CT log, arsip, DNS pasif — semua via engine recon Cyphron, scope "
        "per-destination ditegakkan",
        ["query log sumber publik", "audit.jsonl Cyphron"],
        "Semua sudah jadi bawaan: ct_log/wayback/passive_dns/subdomain_brute"),
]


def catalog(auth_filter: str | None = None) -> list[dict]:
    rows = []
    for t in TRADECRAFT:
        if auth_filter and t.auth != auth_filter:
            continue
        rows.append({
            "id": t.tid, "phase": t.phase, "name": t.name,
            "auth": t.auth, "lab_setup": t.lab_setup,
            "simulation": t.simulation,
            "telemetry": t.telemetry, "purple_note": t.purple_note,
        })
    return rows


def detection_coverage(covered_phases: set[str]) -> dict:
    """Purple-team: teknik yang butuh telemetri fase X — tercakup atau tidak
    oleh engine/engagement (jujur soal gap)."""
    rows = []
    for t in TRADECRAFT:
        rows.append({
            "id": t.tid, "phase": t.phase, "name": t.name,
            "telemetry_required": len(t.telemetry),
            "phase_covered": t.phase in covered_phases,
            "auth": t.auth,
        })
    return {
        "techniques": len(rows),
        "covered": sum(1 for r in rows if r["phase_covered"]),
        "gaps": [r["id"] for r in rows if not r["phase_covered"]],
        "rows": rows,
    }


# ------------------------------------------------------------ C2 sim (RTL-09)
def c2_simulate(host: str = "127.0.0.1", port: int = 0, beacons: int = 3,
                interval_s: float = 0.2, jitter: float = 0.1,
                duration_cap_s: float = 10.0, marker: str = "lab-c2-sim") -> dict:
    """C2-simulation loopback: listener + beacon thread, berbatas.

    Pagar: host WAJIB loopback (ditegakkan kode), jumlah beacon & durasi
    dibatasi, protokol polos (HELLO/TASK/ACK) supaya rule deteksi bisa
    diuji, tanpa persistensi, tanpa payload. Return timeline + hasil uji.
    """
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("c2_simulate hanya boleh loopback (lab)")
    beacons = max(1, min(int(beacons), 10))
    duration_cap_s = min(float(duration_cap_s), 30.0)
    timeline: list[dict] = []

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(beacons)
    srv.settimeout(duration_cap_s)
    bound_port = srv.getsockname()[1]
    tasks: list[str] = []
    deadline = time.monotonic() + duration_cap_s

    def listener_loop():
        while time.monotonic() < deadline and len(timeline) < beacons * 3 + 2:
            try:
                conn, addr = srv.accept()
            except (socket.timeout, OSError):
                return
            with conn:
                conn.settimeout(2.0)
                try:
                    hello = conn.recv(256).decode("utf-8", "replace").strip()
                except OSError:
                    continue
                timeline.append({"t": time.monotonic(), "dir": "in",
                                 "msg": hello})
                task = f"TASK noop-{len(tasks) + 1}"
                tasks.append(task)
                try:
                    conn.sendall(task.encode())
                except OSError:
                    return
                timeline.append({"t": time.monotonic(), "dir": "out",
                                 "msg": task})
                try:
                    ack = conn.recv(256).decode("utf-8", "replace").strip()
                except OSError:
                    ack = ""
                timeline.append({"t": time.monotonic(), "dir": "in",
                                 "msg": ack})

    th = threading.Thread(target=listener_loop, daemon=True)
    th.start()

    started = time.monotonic()
    acks_ok = 0
    for i in range(beacons):
        if time.monotonic() > deadline:
            break
        delay = interval_s + (jitter * (i % 3) / 3.0)
        time.sleep(min(delay, duration_cap_s))
        try:
            c = socket.create_connection((host, bound_port), timeout=2.0)
        except OSError as exc:
            timeline.append({"t": time.monotonic(), "dir": "err",
                             "msg": f"connect: {type(exc).__name__}"})
            continue
        with c:
            c.settimeout(2.0)
            c.sendall(f"HELLO {marker} #{i + 1}".encode())
            data = b""
            try:
                data = c.recv(256)
            except OSError:
                pass
            task = data.decode("utf-8", "replace").strip()
            if task.startswith("TASK"):
                c.sendall(f"ACK {task}".encode())
                acks_ok += 1
    th.join(timeout=2.0)
    srv.close()
    return {
        "marker": marker,
        "listener": f"{host}:{bound_port}",
        "beacons_sent": beacons,
        "acks_ok": acks_ok,
        "tasks_issued": len(tasks),
        "timeline": [
            {**e, "t": round(e["t"] - started, 3)} for e in timeline],
        "duration_s": round(time.monotonic() - started, 3),
        "protocol": "HELLO/TASK/ACK (polos, untuk unit-test rule deteksi)",
        "note": "loopback-only; tidak mengukur deteksi jaringan nyata (RTL-09)",
    }


# ------------------------------------------------- privesc read-only (RTL-04)
def _writable(path: str) -> bool:
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


def privesc_scan() -> dict:
    """Pemindaian read-only misconfig host (lab/engagement): PATH writable,
    world-writable di PATH, SUID di dir biner (POSIX). TANPA eksploitasi."""
    findings: list[dict] = []
    path_dirs = [p for p in os.environ.get("PATH", "").split(os.pathsep)
                 if p and os.path.isdir(p)]
    for d in path_dirs:
        if _writable(d):
            findings.append({"check": "path-dir-writable", "target": d,
                             "severity": "medium",
                             "verdict": ("proses apapun di PATH bisa "
                                         "ditimpa binary (L3 bila "
                                         "disaksikan)")})
        if os.name == "posix":
            try:
                for name in sorted(os.listdir(d))[:400]:
                    fp = os.path.join(d, name)
                    try:
                        st = os.stat(fp)
                    except OSError:
                        continue
                    if st.st_mode & stat.S_IWOTH:
                        findings.append({
                            "check": "world-writable-binary",
                            "target": fp, "severity": "high",
                            "verdict": "binary di PATH world-writable"})
                    if st.st_mode & stat.S_ISUID:
                        findings.append({
                            "check": "suid-binary", "target": fp,
                            "severity": "info",
                            "verdict": ("SUID — review manual apakah "
                                        "perlu (bukan temuan otomatis)")})
            except OSError:
                continue
    return {
        "mode": "read-only (tanpa upaya eskalasi — RTL-04)",
        "path_dirs": len(path_dirs),
        "findings": findings,
        "counts": {
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
        },
    }


def render_lab_report(sim: dict | None = None, privesc: dict | None = None,
                      covered_phases: set[str] | None = None) -> str:
    covered = covered_phases or set()
    cov = detection_coverage(covered)
    lines = [
        "# Engagement Lab Report (red-team berotorisasi)", "",
        f"**Teknik katalog**: {cov['techniques']} · tercakup fase: "
        f"{cov['covered']} · gap: {', '.join(cov['gaps']) or '-'}", "",
        "## 1. Katalog tradecraft (RTL-*)", "",
        "| ID | Fase | Teknik | Otorisasi |", "|---|---|---|---|",
    ]
    for t in TRADECRAFT:
        lines.append(f"| {t.tid} | {t.phase} | {t.name} | {t.auth} |")
    lines += ["", "## 2. Cakupan deteksi (purple-team)", "",
              "| ID | Fase | Telemetri wajib | Fase tercakup |",
              "|---|---|---|---|"]
    for r in cov["rows"]:
        lines.append(f"| {r['id']} | {r['phase']} | "
                     f"{r['telemetry_required']} sumber | "
                     f"{'ya' if r['phase_covered'] else 'GAP'} |")
    if sim:
        lines += ["", "## 3. C2-simulation (RTL-09)", "",
                  f"- Listener: `{sim['listener']}` (loopback)",
                  f"- Beacon: {sim['beacons_sent']} sent, {sim['acks_ok']} ACK",
                  f"- Durasi: {sim['duration_s']}s (bounded)",
                  f"- Protokol: {sim['protocol']}", "",
                  "Timeline (detik relatif):"]
        for e in sim["timeline"][:20]:
            lines.append(f"- t={e['t']} {e['dir']}: {e['msg'][:60]}")
    if privesc:
        lines += ["", "## 4. Privesc read-only (RTL-04)", "",
                  f"- {privesc['mode']}",
                  f"- {privesc['counts']}"]
        for f in privesc["findings"][:15]:
            lines.append(f"- [{f['severity']}] {f['check']}: {f['target']} "
                         f"— {f['verdict']}")
    lines += ["", "## 5. Aturan lab", "",
              "- Snapshot sebelum/sesudah tiap teknik persistence; bukti "
              "rollback wajib ada di laporan.",
              "- Tidak ada payload nyata; marker/aritmetika = bukti "
              "deterministik (L3).",
              "- C2-sim loopback = validasi protokol + rule; bukan pengukuran "
              "deteksi jaringan.", ""]
    return "\n".join(lines)
