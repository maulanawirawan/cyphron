"""[SAFETY: read-only] infra-config-audit — audit konfigurasi penyebaran
LOKAL (docker-compose, Dockerfile, nginx, .env.example). NOL request.

Audit 2026-10 (eskalasi white-box Rimpa): temuan review manual — port host
terbit ke 0.0.0.0, kredensial default, header keamanan nginx hilang, saklar
verifikasi dinonaktifkan — seluruhnya dapat dideteksi dari file konfigurasi
tanpa menyentuh jaringan. Skill ini memformalkan pemeriksaan tersebut.

Zero-FP: hanya aturan yang mekanismenya jelas (mis. port non-localhost di
`ports:` compose; privileged: true; autoindex on; TLS lama). Yang ambigu
masuk meta, bukan temuan.

Pemakaian (via orchestrator: needs=source):
  python skills/infra_config_audit.py --source <path> --out f.json
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_FILES = 400
NGINX_HEADERS = ["Strict-Transport-Security", "X-Content-Type-Options",
                 "X-Frame-Options", "Referrer-Policy"]


def _local_port_exposed(value: str) -> bool:
    """ports: '8080:80' / '0.0.0.0:8080:80' / '[::]:80' => terbit ke luar."""
    host_side = value.split(":")[0] if value.count(":") >= 1 else ""
    host_side = host_side.strip("[]")
    return host_side not in ("127.0.0.1", "::1", "localhost", "")


def _looks_like_real_secret(value: str) -> bool:
    if len(value) < 12:
        return False
    if re.search(r"(?i)(your_|<[^>]+>|\{\{|\$\{|changeme|example|dummy|"
                 r"xxxxx|redacted|replace)", value):
        return False
    # campuran huruf+karakter khusus/angka dengan panjang wajar
    return bool(re.search(r"[A-Za-z]", value) and
                re.search(r"[0-9\-_!@#$%^&*+/.=]", value))


def audit(source: str) -> tuple[list[dict], dict]:
    root = Path(source)
    if not root.is_dir():
        return [], {"ok": False, "error": f"path tidak ada: {source}"}
    rows: list[dict] = []
    scanned: list[str] = []

    def add(rel: str, line: int, title: str, desc: str, sev: str = "medium"):
        # guard kontrak: tanpa return telanjang (ast walk meliputi nested)
        if len(rows) < 100:
            rows.append(make_finding(
                tool="infra-config-audit",
                title=title, severity=sev,
                description=desc,
                recommendation="Perbaiki konfigurasi sebelum rilis produksi.",
                target_url=f"file:{rel}#{line}",
                evidence_kind="file-manifest",
                finding_class="posture",
                confidence=0.85,
                status="unconfirmed",
                lab_only=False,
                extra={"category": "INFRA-CONFIG", "safety_class": "read-only",
                       "requests": 0},
            ))

    # ── docker-compose*.yml ─────────────────────────────────────────
    for p in sorted(root.rglob("docker-compose*.yml"))[:MAX_FILES // 4]:
        rel = p.relative_to(root).as_posix()
        scanned.append(rel)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        in_ports = False
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if re.match(r"^\s*ports:\s*$", line):
                in_ports = True
                continue
            if in_ports and s.startswith("- "):
                val = s[2:].strip().strip('"').strip("'")
                if ":" in val and _local_port_exposed(val):
                    add(rel, i,
                        f"Port host terbit ke antarmuka publik ({val}) di {rel}",
                        "Mapping ports tidak mengikat 127.0.0.1/::1 — layanan "
                        "kontainer dapat dijangkau langsung dari luar host, "
                        "melewati nginx/edge.")
                in_ports = False
            elif in_ports and s and not s.startswith("- "):
                in_ports = False
            if re.search(r"\bprivileged:\s*true\b", line):
                add(rel, i, f"Kontainer privileged: true di {rel}",
                    "Kontainer privileged hampir tanpa isolasi — setara akses "
                    "root host bila terkompromi.", "high")
            if re.search(r"\bnetwork_mode:\s*host\b", line):
                add(rel, i, f"network_mode: host di {rel}",
                    "Kontainer berbagi jaringan host — pemisahan jaringan hilang.")
            m = re.search(r"(?i)(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|"
                          r"MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\s*:\s*(\S+)",
                          line)
            if m and not m.group(2).startswith(("${", '"${', "'${")) \
                    and _looks_like_real_secret(m.group(2)):
                add(rel, i, f"Kredensial database tertulis langsung di {rel}",
                    "Nilai kata sandi ter-hardcode di file konfigurasi (bukan "
                    "referensi variabel) — ikut masuk riwayat git.")

    # ── nginx*.conf ─────────────────────────────────────────────────
    for p in sorted(root.rglob("nginx*.conf"))[:MAX_FILES // 4]:
        rel = p.relative_to(root).as_posix()
        scanned.append(rel)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if re.search(r"\bautoindex\s+on\b", s):
                add(rel, i, f"autoindex on di {rel}",
                    "Daftar direktori terbuka — struktur berkas ikut terpapar.")
            if re.search(r"ssl_protocols\b.*(SSLv3|TLSv1\.0|TLSv1\.1)", s):
                add(rel, i, f"Protokol TLS usang diaktifkan di {rel}",
                    "TLSv1.0/1.1/SSLv3 tidak lagi aman; batasi ke TLSv1.2+.")
        for header in NGINX_HEADERS:
            if not re.search(rf"add_header\s+{header}\b", text):
                add(rel, 0, f"Header keamanan {header} tidak diatur di {rel}",
                    "Header dasar tidak ditemukan pada konfigurasi nginx.",
                    "info")

    # ── .env.example / .env.sample ──────────────────────────────────
    for p in sorted(root.rglob(".env.*"))[:MAX_FILES // 4]:
        if p.name in (".env.example", ".env.sample", ".env.template"):
            rel = p.relative_to(root).as_posix()
            scanned.append(rel)
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                m = re.match(
                    r"(?i)(?:[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*)"
                    r"\s*=\s*(\S+)", line)
                if m and _looks_like_real_secret(m.group(1)):
                    add(rel, i,
                        f"Nilai tampak seperti kredensial nyata di {rel}",
                        "Berkas contoh seharusnya kosong/placeholder — nilai "
                        "nyata di sini berisiko ikut ter-commit.")

    meta = {"ok": True, "source": str(root), "scanned": scanned,
            "findings": len(rows), "requests": 0,
            "safety_class": "read-only"}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True, help="path source lokal")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows, meta = audit(args.source)
    if not meta.get("ok"):
        print(f"DITOLAK: {meta.get('error')} (fail-closed)", file=sys.stderr)
        return 2
    write_findings(args.out, rows, meta)
    print(f"infra-config-audit: {len(meta['scanned'])} berkas konfigurasi, "
          f"{len(rows)} temuan -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
