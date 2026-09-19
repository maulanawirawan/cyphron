"""roadmap_batch4 — 10 slot ROADMAP berikutnya yang diimplementasikan LIVE:
1. ct_conf     (medium-08 content-type-confusion: JSON diterima saat Content-Type salah)
2. verb_over   (medium-09 verb-override: X-HTTP-Method-Override dijalankan)
3. smtp_probe  (medium-14 smtp-starttls-missing: EHLO tanpa STARTTLS)
4. dkim_probe  (medium-15 dkim-weak-key: kunci DKIM < 1024 bit)
5. api_ver     (medium-16 api-version-downgrade: v1 terbuka, v2 terlindungi)
6. gql_batch   (medium-17 graphql-batching: N query dalam 1 request)
7. gql_depth   (medium-18 cost unbounded: 500 alias dijawab server)
8. gql_alias   (medium-19 rest-aliasing: field ganda via alias terbaca)
9. pagin       (medium-20 pagination-unbounded: limit=10000 diterima)
10. sort_inj   (medium-21 sort-filter-injection: error SQL pada param sort)

Truth guarantee: tiap hit = marker/diferensial definitif; server yang menolak
(400/415/401) BUKAN temuan; koneksi gagal (SMTP/DNS) = graceful skip."""

from __future__ import annotations

import base64
import json
import re
import socket
import struct
import time
from urllib.parse import urlencode, urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from .email_probe import apex_of, dns_txt, _read_name, RESOLVERS
from ..findings import Finding

_JSON_CT = "application/json"


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


def is_ip_or_local(domain: str) -> bool:
    """TRUE bila domain adalah alamat IP / localhost / TLD tak-resmi — audit
    DNS (DKIM/MX/CT) tidak berarti untuk itu dan hanya membuang query."""
    d = (domain or "").lower().rstrip(".")
    if d in ("", "localhost", "127.0.0.1", "::1"):
        return True
    # semua label numerik (termasuk '0.1' hasil apex_of atas IP) = IP-ish
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d) or d.replace(".", "").isdigit():
        return True
    return d.endswith((".local", ".test", ".example", ".invalid"))


class CtaConfTool(Tool):
    name = "ct_conf"
    description = "Content-type confusion: body JSON diparse meski Content-Type salah."
    risk_tags = {"active"}
    source_skill = "t2-medium-08"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 10))
        endpoints: list[str] = []
        for ep in ctx.world.endpoints.values():
            if ep.method == "POST" and ep.url not in endpoints:
                endpoints.append(ep.url)
            if len(endpoints) >= 3:
                break
        findings: list[Finding] = []
        tested = 0
        for url in endpoints:
            if tested + 3 > cap:
                break
            marker = f"cyphronct{int(time.time()) % 100000:05d}"
            variants = [
                ("application/x-www-form-urlencoded", urlencode({"q": "x", "extra": marker}).encode()),
                (_JSON_CT, json.dumps({"q": "x", "extra": marker}).encode()),
                ("text/plain", json.dumps({"q": "x", "extra": marker}).encode()),
            ]
            results = []
            for ctype, body in variants:
                if tested + 1 > cap:
                    break
                try:
                    ctx.throttle()
                    st, hd, bd, _m = http_engine.http_get(
                        url, timeout=ctx.timeout_s, method="POST", data=body,
                        headers={"Content-Type": ctype})
                except Exception:
                    continue
                ctx.world.observe_response(url, st, hd, bd, self.name)
                tested += 1
                results.append((ctype, st, bd or ""))
            if len(results) < 3:
                continue
            baseline_status, baseline_body = results[0][1], results[0][2]
            for ctype, st, bd in results[1:]:
                reflected = marker in bd and marker not in baseline_body
                if reflected and st == 200:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Content-type confusion: {ctype} diparse di {url}",
                        severity="medium", cwe="CWE-436",
                        description=(f"Endpoint {url} mem-parsing body berformat JSON meski "
                                     f"Content-Type '{ctype}' — field 'extra' dengan marker "
                                     f"unik dipantulkan balik (baseline form tidak memantulkan). "
                                     f"Parser konten tidak dipilih dari Content-Type."),
                        recommendation="Pilih parser berdasarkan Content-Type dan tolak tipe "
                                       "tak dikenal dengan 415.",
                        target_url=url, request=f"POST {url} (Content-Type: {ctype})",
                        response=f"marker {marker} dipantulkan; baseline tidak",
                        confidence=0.85, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response"))
                    break
                if reflected and st != 200:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Dugaan content-type confusion (marker dipantulkan, status {st})",
                        severity="low", cwe="CWE-436",
                        description=f"{url} memantulkan field JSON meski Content-Type {ctype}.",
                        recommendation="Validasi Content-Type sebelum memilih parser.",
                        target_url=url, request=f"POST {url} ({ctype})",
                        response=f"marker dipantulkan; status {st}", confidence=0.4,
                        source_skill=self.source_skill, status="unconfirmed",
                        evidence_kind="request-response"))
                    break
        ctx.world.note(f"ct_conf: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class VerbOverrideTool(Tool):
    name = "verb_over"
    description = "X-HTTP-Method-Override: metode dibelokkan tanpa validasi."
    risk_tags = {"active"}
    source_skill = "t2-medium-09"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 8))
        endpoints = [ep.url for ep in ctx.world.endpoints.values() if ep.method == "POST"][:3]
        findings: list[Finding] = []
        tested = 0
        delete_re = re.compile(r"(?i)\b(deleted|removed|destroyed|success)\b")
        for url in endpoints:
            if tested + 2 > cap:
                break
            try:
                ctx.throttle()
                sb, hb, bb, _m = http_engine.http_get(
                    url, timeout=ctx.timeout_s, method="POST",
                    data=b"x=1", headers={"Content-Type": "application/x-www-form-urlencoded"})
            except Exception:
                continue
            ctx.world.observe_response(url, sb, hb, bb, self.name)
            tested += 1
            for override in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
                if tested + 1 > cap:
                    break
                try:
                    ctx.throttle()
                    st, hd, bd, _m = http_engine.http_get(
                        url, timeout=ctx.timeout_s, method="POST",
                        data=b"x=1", follow_redirects=False,
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 override: "DELETE"})
                except Exception:
                    continue
                ctx.world.observe_response(url, st, hd, bd, self.name)
                tested += 1
                # FP-guard: respons HARUS menunjukkan eksekusi DELETE (204, atau
                # body kata delete/removed) DAN berbeda dari POST biasa.
                if (st == 204 or delete_re.search(bd or "")) and st != sb:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Verb override {override}: DELETE dieksekusi via POST",
                        severity="medium", cwe="CWE-650",
                        description=(f"POST ke {url} dengan header {override}: DELETE "
                                     f"menghasilkan respons eksekusi DELETE (status {st}, "
                                     f"baseline POST {sb}). Front-end/proxy yang hanya "
                                     f"mengizinkan POST bisa dilewati."),
                        recommendation="Abaikan header override, atau whitelist metode tujuan "
                                       "per endpoint dan cek otorisasi metode hasil override.",
                        target_url=url, request=f"POST {url} ({override}: DELETE)",
                        response=f"override: {st}; baseline POST: {sb}",
                        confidence=0.8, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="probe-pair"))
                    break
        ctx.world.note(f"verb_over: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


def _parse_mx_answers(packet: bytes) -> list[tuple[int, str]]:
    if len(packet) < 12:
        return []
    ancount = struct.unpack("!H", packet[6:8])[0]
    records: list[tuple[int, str]] = []
    offset = 12
    try:
        _n, offset = _read_name(packet, offset)
        offset += 4
        for _ in range(ancount):
            _n, offset = _read_name(packet, offset)
            rtype, _c, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            rdata = packet[offset:offset + rdlength]
            if rtype == 15 and rdlength > 2:
                pref = struct.unpack("!H", rdata[:2])[0]
                exch, _e = _read_name(packet, offset + 2)
                records.append((pref, exch.rstrip(".")))
            offset += rdlength  # maju ke record berikutnya (wajib!)
    except (IndexError, struct.error):
        pass  # respons malformasi/truncated -> kembalikan yang berhasil dibaca
    return records


def dns_mx(name: str, timeout: float = 5.0) -> list[tuple[int, str]]:
    """MX lookup raw-socket stdlib (UDP, fallback TCP saat timeout/TC)."""
    import os as _os
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    header = _os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query = header + labels + b"\x00\x0f\x00\x01"  # qtype=MX
    for resolver in RESOLVERS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packet = None
        try:
            sock.settimeout(timeout)
            sock.sendto(query, (resolver, 53))
            packet, _addr = sock.recvfrom(4096)
        except OSError:
            packet = None
        finally:
            sock.close()
        if packet is not None and len(packet) >= 12:
            records = _parse_mx_answers(packet)
            flags = struct.unpack("!H", packet[2:4])[0]
            if records and not (flags & 0x0200):
                return records
        # UDP timeout / TC / kosong -> coba TCP
        from .email_probe import _dns_query_tcp
        tcp_packet = _dns_query_tcp(query, resolver, timeout)
        if tcp_packet is not None:
            records = _parse_mx_answers(tcp_packet)
            if records:
                return records
    return []


def parse_ehlo_starttls(banner: str) -> bool:
    """FP-guard helper: TRUE hanya bila server mengumumkan STARTTLS di EHLO."""
    return bool(re.search(r"(?im)^\d{3}[ -].*\bSTARTTLS\b", banner or ""))


class SmtpProbeTool(Tool):
    name = "smtp_probe"
    description = ("Cek STARTTLS di MX host: EHLO tanpa STARTTLS = email terkirim "
                   "polos. MX di luar scope otorisasi tidak disentuh (lead pasif).")
    # EHLO aktif ke MX host (host milik pihak ketiga/pemberi layanan email):
    # butuh cek scope per-destination, bukan tag passive.
    risk_tags = {"passive", "active"}
    source_skill = "t2-medium-14"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"])
        domain = str(args.get("domain") or apex_of(urlsplit(base).hostname or ""))
        findings: list[Finding] = []
        if is_ip_or_local(domain):
            return ToolResult(tool=self.name, ok=True, data={"domain": domain, "mx": 0})
        ctx.throttle()
        mxs = dns_mx(domain, timeout=min(ctx.timeout_s, 5.0))
        ctx.world.note(f"smtp_probe: {len(mxs)} MX untuk {domain}")
        if not mxs:
            return ToolResult(tool=self.name, ok=True, data={"mx": 0})
        mxs.sort()
        pref, host = mxs[0]
        # MX host adalah DESTINASI berbeda dari target: wajib in-scope sebelum
        # satu pun koneksi. Tanpa izin: catat sebagai lead pasif, NOL koneksi.
        decision = ctx.gate.evaluate_host(host, 25)
        ctx.audit.append({"kind": "host-scope-decision", "tool": self.name,
                          "host": host, "port": 25, "allowed": decision.allowed,
                          "reason": decision.reason})
        if not decision.allowed:
            ctx.world.note(f"smtp_probe: MX {host} di luar scope otorisasi — "
                           f"EHLO aktif dilewati, lead pasif saja")
            return ToolResult(tool=self.name, ok=True,
                              data={"mx": len(mxs), "skipped": host})
        ctx.throttle()
        try:
            sock = socket.create_connection((host, 25), timeout=ctx.timeout_s)
            sock.settimeout(ctx.timeout_s)
            banner = sock.recv(1024).decode("latin-1", "replace")
            sock.sendall(f"EHLO cyphron-probe.example\r\n".encode())
            time.sleep(0.3)
            ehlo = b""
            while True:
                try:
                    chunk = sock.recv(2048)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                ehlo += chunk
                if b"250 " in ehlo.split(b"250-", 1)[-1]:
                    break
            sock.close()
        except OSError as exc:
            ctx.world.note(f"smtp_probe: port 25 {host} tidak terjangkau ({type(exc).__name__})")
            return ToolResult(tool=self.name, ok=True, data={"mx": len(mxs), "error": "blocked"})
        ehlo_text = (banner + "\r\n" + ehlo.decode("latin-1", "replace"))
        ctx.world.request_count += 1
        if not ehlo_text.startswith("2"):
            ctx.world.note(f"smtp_probe: {host} banner tidak 2xx")
            return ToolResult(tool=self.name, ok=True, data={"mx": len(mxs), "banner": "non-2xx"})
        if not parse_ehlo_starttls(ehlo_text):
            findings.append(Finding(
                tool=self.name,
                title=f"SMTP tanpa STARTTLS di {host} ({domain})",
                severity="medium", cwe="CWE-319",
                description=(f"MX utama {host} (preferensi {pref}) menerima EHLO TANPA "
                             f"mengumumkan STARTTLS. Mail ke {domain} dapat disadap "
                             f"opportunistically di jalur."),
                recommendation="Aktifkan STARTTLS (dan pertimbangkan MTA-STS + DANE) "
                               "pada MX server.",
                target_url=f"smtp://{host}:25", request=f"EHLO cyphron-probe.example -> {host}:25",
                response=ehlo_text[:300], confidence=0.9, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        return ToolResult(tool=self.name, ok=True, data={"mx": len(mxs)}, findings=findings)


def dkim_key_bits(txt_record: str) -> int | None:
    """Ekstrak panjang modulus kunci publik (bit) dari record DKIM TXT.
    None = bukan kunci RSA (mis. ed25519) atau record tanpa kunci."""
    m = re.search(r"p=([A-Za-z0-9+/=]+)", txt_record or "")
    if not m:
        return None
    try:
        der = base64.b64decode(m.group(1))
    except Exception:
        return None
    if len(der) < 2 or der[0] != 0x30:
        return None
    # lewati header SEQUENCE
    i = 1
    if der[i] & 0x80:
        n = der[i] & 0x7F
        i += 1 + n
    else:
        i += 1
    # INTEGER pertama = modulus
    if i >= len(der) or der[i] != 0x02:
        return None
    i += 1
    if der[i] & 0x80:
        n = der[i] & 0x7F
        ln = int.from_bytes(der[i + 1:i + 1 + n], "big")
        i += 1 + n
    else:
        ln = der[i]
        i += 1
    mod = der[i:i + ln]
    if not mod:
        return None
    lead = 0
    for bit in range(7, -1, -1):
        if (mod[0] >> bit) & 1:
            break
        lead += 1
    return ln * 8 - lead


DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "k1",
                  "dkim", "mail", "smtp", "mandrill", "zoho", "protonmail", "everlytickey1",
                  "everserving", "dkim1024", "dkim2048", "smtp2go", "sendgrid", "cisco")


class DkimProbeTool(Tool):
    name = "dkim_probe"
    description = "Audit kunci DKIM selector umum: kunci < 1024 bit dapat dipecahkan."
    risk_tags = {"passive"}
    source_skill = "t2-medium-15"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"])
        domain = str(args.get("domain") or apex_of(urlsplit(base).hostname or ""))
        cap = int(args.get("max_requests", 10))
        findings: list[Finding] = []
        checked = 0
        if is_ip_or_local(domain):
            ctx.world.note(f"dkim_probe: {domain} adalah IP/lokal — audit dilewati")
            return ToolResult(tool=self.name, ok=True, data={"domain": domain, "checked": 0})
        for selector in DKIM_SELECTORS[:cap]:
            name = f"{selector}._domainkey.{domain}"
            ctx.throttle()
            try:
                txts = __import__("cyphron.tools.email_probe", fromlist=["dns_txt"]) \
                    .dns_txt(name, timeout=min(ctx.timeout_s, 4.0))
            except Exception:
                continue
            checked += 1
            for txt in txts:
                bits = dkim_key_bits(txt)
                if bits is not None and bits < 1024:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Kunci DKIM lemah ({bits} bit) pada {name}",
                        severity="medium", cwe="CWE-326",
                        description=(f"Selector DKIM '{selector}' di {domain} mempublikasikan "
                                     f"kunci RSA {bits} bit (< 1024). Kunci sekecil ini dapat "
                                     f"di-faktorkan sehingga penyerang dapat menandatangani "
                                     f"email palsu yang lolos verifikasi DKIM."),
                        recommendation="Rotasi ke kunci RSA >= 2048 bit (atau Ed25519).",
                        target_url=f"dns:{name}", request=f"TXT {name}",
                        response=f"kunci {bits} bit", confidence=0.95,
                        source_skill=self.source_skill, status="confirmed",
                        evidence_kind="request-response"))
                    break
        ctx.world.note(f"dkim_probe: {checked} selector diuji di {domain}, "
                       f"{len(findings)} kunci lemah")
        return ToolResult(tool=self.name, ok=True, data={"checked": checked}, findings=findings)


class ApiVerTool(Tool):
    name = "api_ver"
    description = "API version downgrade: versi lama terbuka sementara versi baru terlindungi."
    risk_tags = {"active"}
    source_skill = "t2-medium-16"

    RESOURCES = ("/users", "/me", "/orders", "/profile", "")

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 10))
        findings: list[Finding] = []
        tested = 0
        # Resource path dipilih dari endpoint /api yang sudah teramati bila ada
        api_prefixes = ["/api/v1", "/api/v2", "/api/v3"]
        for res in self.RESOURCES:
            if tested >= cap:
                break
            statuses = {}
            for ver in api_prefixes:
                if tested + 1 > cap:
                    break
                url = urljoin(base + "/", ver.lstrip("/") + res)
                try:
                    ctx.throttle()
                    st, hd, bd, _m = http_engine.http_get(url, timeout=ctx.timeout_s,
                                                          follow_redirects=False)
                except Exception:
                    continue
                ctx.world.observe_response(url, st, hd, bd, self.name)
                tested += 1
                statuses[ver] = (st, bd or "")
            v1 = statuses.get("/api/v1")
            v2 = statuses.get("/api/v2")
            # FP-guard: hit hanya bila v1 200-berisi-data dan v2 justru menolak 401/403
            if (v1 and v2 and v1[0] == 200 and v2[0] in (401, 403)
                    and len(v1[1]) > 20):
                findings.append(Finding(
                    tool=self.name,
                    title=f"API v1 masih terbuka tanpa auth (v2 menolak): {res or '/'}",
                    severity="medium", cwe="CWE-1104",
                    description=(f"GET {base}/api/v1{res} mengembalikan 200 berisi data, "
                                 f"sementara /api/v2{res} menuntut otentikasi ({v2[0]}). "
                                 f"Versi lama tidak menikmati kontrol akses versi baru — "
                                 f"downgrade path untuk akses tanpa kredensial."),
                    recommendation="Matikan/nonaktifkan versi API lama; terapkan middleware "
                                   "auth yang sama lintas versi.",
                    target_url=f"{base}/api/v1{res}",
                    request=f"GET /api/v1{res} vs /api/v2{res}",
                    response=f"v1: 200 len={len(v1[1])}; v2: {v2[0]}",
                    poc=f"curl -s '{base}/api/v1{res}'",
                    confidence=0.85, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="probe-pair"))
        ctx.world.note(f"api_ver: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class _GqlBase(Tool):
    """Discovery bersama endpoint GraphQL."""

    DEFAULTS = ("/graphql", "/api/graphql", "/graphiql", "/api/v1/graphql", "/v1/graphql")

    def _endpoints(self, ctx: ToolContext, base: str) -> list[str]:
        paths: list[str] = []
        for ep in ctx.world.endpoints.values():
            p = urlsplit(ep.url).path.lower()
            if "graphql" in p and p not in paths:
                paths.append(p)
        for p in self.DEFAULTS:
            if len(paths) >= 3:
                break
            if p not in paths:
                paths.append(p)
        return [urljoin(base + "/", p.lstrip("/")) for p in paths[:3]]

    def _post(self, url: str, payload: dict | list, ctx: ToolContext):
        try:
            ctx.throttle()
            st, hd, bd, _m = http_engine.http_get(
                url, timeout=ctx.timeout_s, method="POST",
                data=json.dumps(payload).encode(), headers={"Content-Type": _JSON_CT})
        except Exception:
            return None
        ctx.world.observe_response(url, st, hd, bd, self.name)
        ctx.world.request_count += 1
        try:
            parsed = json.loads(bd or "")
        except json.JSONDecodeError:
            parsed = None
        return st, bd or "", parsed


class GqlBatchTool(_GqlBase):
    name = "gql_batch"
    description = "GraphQL batching: array-of-queries dieksekusi dalam 1 request."
    risk_tags = {"active"}
    source_skill = "t2-medium-17"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        for url in self._endpoints(ctx, base):
            single = self._post(url, {"query": "{__typename}"}, ctx)
            if not single or single[0] in (400, 401, 403, 404, 405):
                continue  # FP-guard: endpoint bukan GraphQL valid/terbuka -> skip
            batch = self._post(url, [{"query": "{__typename}"}, {"query": "{__typename}"},
                                     {"query": "{__typename}"}], ctx)
            if not batch:
                continue
            st, bd, parsed = batch
            if (st == 200 and isinstance(parsed, list) and len(parsed) >= 3
                    and all(isinstance(x, dict) and "data" in x for x in parsed)):
                findings.append(Finding(
                    tool=self.name,
                    title=f"GraphQL batching aktif di {urlsplit(url).path}",
                    severity="medium", cwe="CWE-770",
                    description=(f"Endpoint {url} mengeksekusi 3 query dalam satu request "
                                 f"(respons JSON array berisi 3 objek data). Batching "
                                 f"melewati rate-limit per-query dan memperbesar amplifikasi."),
                    recommendation="Matikan array-of-queries (atau batasi ukuran batch) dan "
                                   "hitung cost total per request.",
                    target_url=url, request='POST [{"query":...} x3]',
                    response=f"{st}: array {len(parsed)} data", confidence=0.9,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="request-response"))
        ctx.world.note(f"gql_batch: {len(findings)} endpoint batching")
        return ToolResult(tool=self.name, ok=True, data={}, findings=findings)


class GqlDepthTool(_GqlBase):
    name = "gql_depth"
    description = "GraphQL query cost unbounded: 500 alias dalam 1 query dijawab."
    risk_tags = {"active"}
    source_skill = "t2-medium-18"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        for url in self._endpoints(ctx, base):
            single = self._post(url, {"query": "{__typename}"}, ctx)
            if not single or single[0] in (400, 401, 403, 404, 405):
                continue
            wide_query = "{ " + " ".join(f"f{i}: __typename" for i in range(500)) + " }"
            wide = self._post(url, {"query": wide_query}, ctx)
            if not wide:
                continue
            st, bd, parsed = wide
            resolved = 0
            if isinstance(parsed, dict):
                data = parsed.get("data") or {}
                resolved = len(data) if isinstance(data, dict) else 0
            if st == 200 and resolved >= 400:
                findings.append(Finding(
                    tool=self.name,
                    title=f"GraphQL cost unbounded: {resolved} field dijawab dalam 1 query",
                    severity="medium", cwe="CWE-400",
                    description=(f"{url} menerima query berisi 500 alias dan menjawab "
                                 f"{resolved} field (200). Tanpa batas depth/cost, satu "
                                 f"request bisa memicu kerja berat dan DoS sumber daya."),
                    recommendation="Terapkan query depth/complexity limit dan pagination "
                                   "di resolver.",
                    target_url=url, request="POST query 500 alias",
                    response=f"{st}: {resolved} field terjawab", confidence=0.9,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="request-response"))
        ctx.world.note(f"gql_depth: {len(findings)} endpoint cost-unbounded")
        return ToolResult(tool=self.name, ok=True, data={}, findings=findings)


class GqlAliasTool(_GqlBase):
    name = "gql_alias"
    description = "GraphQL aliasing: field digandakan dalam satu request."
    risk_tags = {"active"}
    source_skill = "t2-medium-19"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        for url in self._endpoints(ctx, base):
            single = self._post(url, {"query": "{__typename}"}, ctx)
            if not single or single[0] in (400, 401, 403, 404, 405):
                continue
            alias_q = '{ a1: __typename a2: __typename a3: __typename }'
            res = self._post(url, {"query": alias_q}, ctx)
            if not res:
                continue
            st, bd, parsed = res
            keys = set((parsed or {}).get("data") or {}) if isinstance(parsed, dict) else set()
            if st == 200 and {"a1", "a2", "a3"} <= keys:
                findings.append(Finding(
                    tool=self.name,
                    title=f"GraphQL aliasing bebas di {urlsplit(url).path}",
                    severity="low", cwe="CWE-770",
                    description=(f"Alias ganda (a1/a2/a3: __typename) semuanya terjawab di "
                                 f"{url}. Aliasing tanpa dedup memungkinkan duplikasi field "
                                 f"mahal dalam 1 request (amplifikasi)."),
                    recommendation="Batasi jumlah alias dan dedup field identik per query.",
                    target_url=url, request=f"POST {alias_q}",
                    response=f"{st}: keys={sorted(keys)[:5]}", confidence=0.85,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="request-response"))
        ctx.world.note(f"gql_alias: {len(findings)} endpoint aliasing")
        return ToolResult(tool=self.name, ok=True, data={}, findings=findings)


class PaginationTool(Tool):
    name = "pagin"
    description = "Pagination unbounded: limit/first=10000 diterima (dump massal)."
    risk_tags = {"active"}
    source_skill = "t2-medium-20"

    PARAMS = {"limit", "first", "size", "per_page", "pagesize", "page_size", "count", "take", "n"}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cap = int(args.get("max_requests", 10))
        findings: list[Finding] = []
        tested = 0
        for ep in ctx.world.param_endpoints(limit=12):
            if tested + 2 > cap:
                break
            for param in ep.params[:3]:
                if param.lower() not in self.PARAMS or tested + 2 > cap:
                    continue
                probe_url = ep.url.split("?", 1)[0]
                try:
                    ctx.throttle()
                    sb, hb, bb, _m = http_engine.http_get(
                        f"{probe_url}?{urlencode({param: 10})}", timeout=ctx.timeout_s)
                    ctx.world.observe_response(f"{probe_url}?{param}=10", sb, hb, bb, self.name)
                    ctx.throttle()
                    st, hd, bd, _m = http_engine.http_get(
                        f"{probe_url}?{urlencode({param: 10000})}", timeout=ctx.timeout_s)
                    ctx.world.observe_response(f"{probe_url}?{param}=10000", st, hd, bd, self.name)
                except Exception:
                    continue
                tested += 2
                # FP-guard: keduanya 200 dan respons 10000x >= 3x respons limit kecil
                if sb == 200 and st == 200 and len(bd or "") > 3 * max(len(bb or ""), 1) \
                        and len(bd or "") > 1000:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Pagination unbounded: {param}=10000 diterima di {probe_url}",
                        severity="medium", cwe="CWE-770",
                        description=(f"{probe_url} menerima {param}=10000 dan mengembalikan "
                                     f"{len(bd)} byte vs {len(bb)} byte pada {param}=10. "
                                     f"Satu request dapat men-dump seluruh koleksi."),
                        recommendation="Batasi nilai limit maksimum di server (hard cap) dan "
                                       "pakai cursor pagination.",
                        target_url=probe_url, param=param,
                        request=f"GET {probe_url}?{param}=10 vs =10000",
                        response=f"len(10)={len(bb)}; len(10000)={len(bd)}",
                        poc=f"curl -s '{probe_url}?{param}=10000' | wc -c",
                        confidence=0.85, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="probe-pair"))
        ctx.world.note(f"pagin: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class SortFilterTool(Tool):
    name = "sort_inj"
    description = "Injeksi pada param sort/order/filter (error DB = terkonfirmasi)."
    risk_tags = {"active"}
    source_skill = "t2-medium-21"

    PARAMS = {"sort", "order", "orderby", "order_by", "filter", "sort_by", "sortby"}
    ERROR_RE = re.compile(
        r"(?i)(sql(?:ite|server)?(?:Exception|error|syntax)|ORA-\d+|psycopg|mysql|"
        r"pg_query|syntax error|invalid.*column|unknown column|ambiguous column)")

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cap = int(args.get("max_requests", 10))
        findings: list[Finding] = []
        tested = 0
        payloads = ("(SELECT 1)", "1;(SELECT 1)--", "name--", "id)) UNION SELECT 1--")
        for ep in ctx.world.param_endpoints(limit=10):
            if tested + 2 > cap:
                break
            for param in ep.params[:3]:
                if param.lower() not in self.PARAMS or tested + 2 > cap:
                    continue
                probe_url = ep.url.split("?", 1)[0]
                try:
                    ctx.throttle()
                    sb, hb, bb, _m = http_engine.http_get(
                        f"{probe_url}?{urlencode({param: 'name'})}", timeout=ctx.timeout_s)
                    ctx.world.observe_response(f"{probe_url}?{param}=name", sb, hb, bb, self.name)
                except Exception:
                    continue
                tested += 1
                if sb != 200 or self.ERROR_RE.search(bb or ""):
                    continue  # baseline sudah error -> tidak bisa diferensial
                for payload in payloads[:2]:
                    if tested + 1 > cap:
                        break
                    try:
                        ctx.throttle()
                        st, hd, bd, _m = http_engine.http_get(
                            f"{probe_url}?{urlencode({param: payload})}", timeout=ctx.timeout_s)
                    except Exception:
                        continue
                    ctx.world.observe_response(f"{probe_url}?{param}=<payload>", st, hd, bd, self.name)
                    tested += 1
                    if st >= 500 and self.ERROR_RE.search(bd or ""):
                        findings.append(Finding(
                            tool=self.name,
                            title=f"Sort/filter injection terkonfirmasi pada '{param}'",
                            severity="medium", cwe="CWE-89",
                            description=(f"Payload SQL pada {param} membuat {probe_url} berubah "
                                         f"200->500 dengan pesan error database. Nilai sort/filter "
                                         f"masuk ke query tanpa sanitasi."),
                            recommendation="Whitelist kolom sort/filter; jangan interpolasi nilai "
                                           "ke SQL; gunakan ORM mapping ketat.",
                            target_url=probe_url, param=param,
                            request=f"GET {probe_url}?{param}={payload}",
                            response=(bd or "")[:180], confidence=0.8,
                            source_skill=self.source_skill, status="confirmed",
                            evidence_kind="request-response"))
                        break
        ctx.world.note(f"sort_inj: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)
