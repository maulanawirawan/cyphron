"""roadmap_batch3 — 10 slot ROADMAP berikutnya yang diimplementasikan LIVE:
1. wayback    (low-02  wayback-diff: rute historis vs sekarang)
2. id_seq     (low-17  sequential-user-id: ID terhitung)
3. ct_log     (low-29  subdomain-ct-audit: CT log membocorkan subdomain)
4. smuggle    (medium-01 smuggling-clue: divergensi CL/TE terkontrol)
5. cache_dec  (medium-02 cache-deception: .css menyajikan halaman akun)
6. oauth      (medium-03/04/05 state-missing, redirect-lax, nonce-missing)
7. puzzle     (medium-06 session-puzzling: string vs array)
8. json_inj   (medium-07 json-injection: struktur JSON berubah terverifikasi)

Semua predikat hit = marker/diferensial definitif (truth guarantee):
- wayback  : arsip 200 + live 404/410 (rute hilang) — bukan sekadar ada di arsip
- id_seq   : dua ID berurutan 200 dengan isi berbeda + kontrol jauh GAGAL
- ct_log   : nama dari CT log yang match ketat domain; www/apex tidak dilaporkan
- smuggle  : baseline cepat + varian timeout konsisten 2x (bukan server lambat)
- cache_dec: body .css mirip halaman akun DAN beda dari body 404 kontrol
- oauth    : 302 Location persis canary (bukan redirect sama-origin), client_id
             tidak ditolak (400/401/403 = server validasi -> bukan temuan)
- puzzle   : baseline password salah GAGAL lalu payload type-confusion SUKSES
- json_inj : kunci 'injected_key' + marker unik muncul di respons (dan TIDAK
             ada di baseline); 500 json-parse = lead unconfirmed saja"""

from __future__ import annotations

import difflib
import json
import re
import socket
import ssl
import time
from urllib.parse import quote, urlencode, urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_CANARY = "https://cyphron-canary.example/cb"
_CANARY_ORIGIN = "https://cyphron-canary.example"
_MARKER = "cyphron7f3a"


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


def _json_key_injected(body: str) -> bool:
    """TRUE hanya jika 'injected_key' adalah KUNCI OBJEK sungguhan dengan nilai
    marker (struktur JSON berubah). Refleksi ter-escape dari json.dumps yang
    benar TIDAK dihitung — mencegah FP pada aplikasi yang men-escape dengan benar."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        data = None
    if data is not None:
        stack = [data]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                if cur.get("injected_key") == _MARKER:
                    return True
                stack.extend(cur.values())
            elif isinstance(cur, list):
                stack.extend(cur)
        return False
    # body bukan JSON valid: pakai pola kunci yang tidak ter-escape
    return re.search(r'(?<!\\)"injected_key"\s*:\s*"' + _MARKER + r'"', body) is not None


class WaybackTool(Tool):
    name = "wayback"
    description = "Wayback diff: rute yang dulu hidup (arsip 200) tapi kini 404/410."
    risk_tags = {"passive"}
    source_skill = "t2-low-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).netloc
        hostname = (urlsplit(base).hostname or "").lower()
        cdx_base = str(args.get("cdx_base") or "https://web.archive.org/cdx/search/cdx")
        # Host privat/loopback tidak ada di arsip publik — lewati hanya saat
        # memakai CDX asli (cdx_base eksplisit = sumber arsip internal/mock)
        if (args.get("cdx_base") is None and
                (not hostname or hostname in ("127.0.0.1", "localhost", "::1")
                 or hostname.endswith(".local") or hostname.startswith("192.168.")
                 or hostname.startswith("10.")
                 or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", hostname))):
            ctx.world.note("wayback: host privat/lokal — audit arsip dilewati")
            return ToolResult(tool=self.name, ok=True, data={"skipped": "private-host"})
        max_paths = min(int(args.get("max_paths", 20)), 30)
        query = (f"{cdx_base}?url={quote(host + '/*', safe='')}&output=json"
                 f"&fl=original,statuscode&collapse=urlkey&filter=statuscode:200&limit=300")
        try:
            status, _h, body, _ms = http_engine.http_get(query, timeout=max(ctx.timeout_s, 30.0))
        except Exception as exc:
            ctx.world.note(f"wayback: CDX tidak terjangkau ({type(exc).__name__})")
            return ToolResult(tool=self.name, ok=True, data={"cdx": "unreachable"})
        if status != 200 or not (body or "").startswith("["):
            ctx.world.note(f"wayback: CDX status {status}")
            return ToolResult(tool=self.name, ok=True, data={"cdx_status": status})
        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            return ToolResult(tool=self.name, ok=True, data={"cdx": "unparsable"})
        assets = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                  ".woff", ".woff2", ".ttf", ".map", ".pdf", ".mp4", ".webp")
        seen: list[str] = []
        for row in rows[1:] if rows and isinstance(rows[0], list) else rows:
            if len(row) < 2 or str(row[1]) != "200":
                continue  # FP-guard: hanya snapshot yang benar-benar 200
            path = urlsplit(str(row[0])).path or "/"
            if path.endswith(assets) or path in seen:
                continue
            seen.append(path)
        lost, alive, tested = [], 0, 0
        for path in seen:
            if tested >= max_paths or ctx.world.request_count >= ctx.max_requests:
                break
            url = urljoin(base + "/", path.lstrip("/"))
            try:
                ctx.throttle()
                st, hd, bd, _m = http_engine.http_get(url, timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.observe_response(url, st, hd, bd, self.name)
            tested += 1
            if st in (404, 410):
                lost.append(path)
            elif st == 200:
                alive += 1
        ctx.world.note(f"wayback: {len(seen)} rute historis, {tested} diuji live, "
                       f"{alive} masih hidup, {len(lost)} hilang")
        findings: list[Finding] = []
        if lost:
            findings.append(Finding(
                tool=self.name,
                title=f"Wayback diff: {len(lost)} rute historis kini hilang (lead recon)",
                severity="low", cwe="CWE-538",
                description=(f"Arsip web merekam {len(seen)} rute pada {host} dengan status 200; "
                             f"{len(lost)} di antaranya kini 404/410. Rute yang dihapus sering "
                             f"masih ada di cache/arsip dan memberi peta attack surface lama. "
                             f"Contoh: {'; '.join(lost[:6])}"),
                recommendation="Periksa apakah rute lama masih mengekspos data via arsip/cache; "
                               "kembalikan 410 eksplisit untuk konten sensitif yang dihapus.",
                target_url=base, request=f"GET {query[:120]}...",
                response=f"lost={lost[:8]}", poc="\n".join(f"curl -s -o /dev/null -w '%{{http_code}}' {urljoin(base + '/', p.lstrip('/'))}" for p in lost[:3]),
                confidence=0.85, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        return ToolResult(tool=self.name, ok=True, data={"tested": tested, "lost": len(lost)},
                          findings=findings)


class IdSeqTool(Tool):
    name = "id_seq"
    description = "Deteksi ID sekuensial yang bisa dihitung (dengan kontrol gagal)."
    risk_tags = {"active"}
    source_skill = "t2-low-17"

    ID_PARAMS = {"id", "uid", "user_id", "userid", "account_id", "acct", "ref",
                 "pid", "num", "order_id", "invoice_id", "doc_id", "item_id"}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 18))
        findings: list[Finding] = []
        tested = 0
        for ep in ctx.world.param_endpoints(limit=12):
            if tested >= cap or ctx.world.request_count >= ctx.max_requests:
                break
            for param in ep.params[:4]:
                if param.lower() not in self.ID_PARAMS or tested + 3 > cap:
                    continue
                probe_url = ep.url.split("?", 1)[0]
                results: dict[str, tuple[int, str]] = {}
                ok_loop = True
                for value in ("1", "2", "99999999"):
                    try:
                        ctx.throttle()
                        st, hd, bd, _m = http_engine.http_get(
                            f"{probe_url}?{urlencode({param: value})}", timeout=ctx.timeout_s)
                    except Exception:
                        ok_loop = False
                        break
                    ctx.world.observe_response(f"{probe_url}?{param}={value}", st, hd, bd, self.name)
                    results[value] = (st, bd or "")
                    tested += 1
                if not ok_loop or len(results) != 3:
                    continue
                s1, b1 = results["1"]
                s2, b2 = results["2"]
                sc, _bc = results["99999999"]
                # FP-guard: kedua ID berurutan 200, isi BERBEDA, dan kontrol jauh GAGAL
                if s1 == 200 and s2 == 200 and b1.strip() != b2.strip() and sc in (400, 401, 403, 404, 410):
                    findings.append(Finding(
                        tool=self.name,
                        title=f"ID sekuensial dapat dihitung pada param '{param}'",
                        severity="low", cwe="CWE-639",
                        description=(f"Endpoint {probe_url} melayani {param}=1 dan {param}=2 dengan "
                                     f"isi berbeda (keduanya 200), sementara {param}=99999999 gagal. "
                                     f"Identifier terlihat berurutan dan enumerable."),
                        recommendation="Gunakan identifier acak (UUID/opaque) atau otorisasi per-objek.",
                        target_url=probe_url, param=param,
                        request=f"GET {probe_url}?{param}=1 / =2 / =99999999",
                        response=f"id=1: {s1} len={len(b1)}; id=2: {s2} len={len(b2)}; "
                                 f"control 99999999: {sc}",
                        poc=f"curl -s '{probe_url}?{param}=1'; curl -s '{probe_url}?{param}=2'",
                        confidence=0.8, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="probe-pair"))
                    break  # satu temuan per endpoint cukup
        ctx.world.note(f"id_seq: {tested} request, {len(findings)} endpoint enumerable")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class CtLogTool(Tool):
    name = "ct_log"
    description = "Certificate Transparency: inventaris nama host di log publik."
    risk_tags = {"passive"}
    source_skill = "t2-low-29"

    SENSITIVE = ("dev", "test", "staging", "stage", "uat", "vpn", "internal", "intranet",
                 "jenkins", "git", "gitlab", "ci", "admin", "panel", "db", "mysql",
                 "postgres", "redis", "kibana", "grafana", "mail", "smtp", "backup",
                 "old", "legacy", "int", "preprod", "sandbox")

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        from .email_probe import apex_of
        from .roadmap_batch4 import is_ip_or_local
        domain = str(args.get("domain") or apex_of(urlsplit(base).hostname or ""))
        domain = domain.lower().removeprefix("www.")
        crt_base = str(args.get("crt_base") or "https://crt.sh")
        if (args.get("crt_base") is None and args.get("domain") is None
                and is_ip_or_local(domain)):
            ctx.world.note("ct_log: domain target tidak cocok untuk audit CT")
            return ToolResult(tool=self.name, ok=True, data={"domain": domain})
        names, source = self._query_crtsh(crt_base, domain, ctx)
        if names is None:
            names, source = self._query_certspotter(str(args.get("certspotter_base")
                                                        or "https://api.certspotter.com"),
                                                    domain, ctx)
        if names is None:
            ctx.world.note("ct_log: semua sumber CT tidak terjangkau (crt.sh + certspotter)")
            return ToolResult(tool=self.name, ok=True, data={"ct": "unreachable"})
        ordered = sorted(names)
        ctx.world.note(f"ct_log: {len(ordered)} subdomain unik dari {source}")
        findings: list[Finding] = []
        if ordered:
            sensitive = [n for n in ordered if any(k in n.split(".")[0] for k in self.SENSITIVE)]
            sev = "low" if sensitive else "info"
            # Semantik temuan (precision layer): hanya OBSERVASI objektif yang
            # confirmed. Label "sensitif" adalah HEURISTIK nama (bukan fakta,
            # wajib disebut sebagai kandidat), dan DAMPAK tidak diklaim -
            # keputusan sebuah host boleh publik sepenuhnya milik policy owner.
            title = (f"Attack surface disclosure: {len(ordered)} nama subdomain via CT log"
                     + (f" ({len(sensitive)} kandidat sensitif - heuristik nama)"
                        if sensitive else ""))
            desc = (f"OBSERVASI (terkonfirmasi): {len(ordered)} nama hostname untuk "
                    f"{domain} teramati pada Certificate Transparency log publik "
                    f"(sumber: {source}).")
            if sensitive:
                desc += (f" KANDIDAT SENSITIF (HEURISTIK, BUKAN FAKTA): {len(sensitive)} "
                         f"nama memenuhi daftar kata kunci heuristik - statusnya "
                         f"kandidat sensitif berdasarkan heuristik nama, perlu "
                         f"konfirmasi policy owner. Kandidat: {'; '.join(sensitive[:8])}.")
            desc += (f" DAMPAK: tidak diklaim. Log CT memang dirancang publik; "
                     f"penilaian apakah sebuah nama host boleh diketahui publik "
                     f"sepenuhnya milik policy pemilik domain. Temuan ini adalah "
                     f"pengungkapan attack surface, bukan kerentanan. "
                     f"Semua nama: {'; '.join(ordered[:15])}"
                     + (f" (+{len(ordered) - 15} lainnya)" if len(ordered) > 15 else ""))
            findings.append(Finding(
                tool=self.name,
                title=title,
                severity=sev, cwe=None,
                description=desc,
                recommendation=("Cocokkan daftar nama di atas dengan daftar aset resmi "
                                "pemilik domain. Untuk host yang memang tidak untuk "
                                "publik, gunakan sertifikat internal/mTLS sehingga "
                                "namanya tidak masuk log CT publik."),
                target_url=base, request=f"CT query {domain} via {source}",
                response="; ".join(ordered[:30]),
                confidence=0.9, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response",
                finding_class="surface"))
        return ToolResult(tool=self.name, ok=True,
                          data={"names": len(ordered), "source": source}, findings=findings)

    def _query_crtsh(self, crt_base: str, domain: str, ctx: ToolContext) -> tuple[set[str] | None, str]:
        query = f"{crt_base.rstrip('/')}/?q={quote('%25.' + domain, safe='')}&output=json"
        try:
            status, _h, body, _ms = http_engine.http_get(query, timeout=max(ctx.timeout_s, 20.0))
        except Exception as exc:
            ctx.world.note(f"ct_log: crt.sh tidak terjangkau ({type(exc).__name__})")
            return None, ""
        if status != 200:
            ctx.world.note(f"ct_log: crt.sh status {status}")
            return None, ""
        try:
            entries = json.loads(body)
        except json.JSONDecodeError:
            return None, ""
        name_re = re.compile(r"^[a-z0-9._-]+$")
        names: set[str] = set()
        for entry in entries if isinstance(entries, list) else []:
            raw = str(entry.get("name_value", ""))
            for n in raw.replace("*.", "").split("\n"):
                n = n.strip().lower().rstrip(".")
                if (n.endswith("." + domain) and n not in (domain, f"www.{domain}")
                        and name_re.match(n)):
                    names.add(n)
        return names, "crt.sh"

    def _query_certspotter(self, base_url: str, domain: str,
                           ctx: ToolContext) -> tuple[set[str] | None, str]:
        query = (f"{base_url.rstrip('/')}/v1/issuances?domain={quote(domain, safe='')}"
                 f"&include_subdomains=true&expand=dns_names")
        try:
            status, _h, body, _ms = http_engine.http_get(query, timeout=max(ctx.timeout_s, 20.0))
        except Exception as exc:
            ctx.world.note(f"ct_log: certspotter tidak terjangkau ({type(exc).__name__})")
            return None, ""
        if status != 200:
            ctx.world.note(f"ct_log: certspotter status {status}")
            return None, ""
        try:
            entries = json.loads(body)
        except json.JSONDecodeError:
            return None, ""
        name_re = re.compile(r"^[a-z0-9._-]+$")
        names: set[str] = set()
        for entry in entries if isinstance(entries, list) else []:
            for n in (entry.get("dns_names") or []):
                n = str(n).lower().replace("*.", "").rstrip(".")
                if (n.endswith("." + domain) and n not in (domain, f"www.{domain}")
                        and name_re.match(n)):
                    names.add(n)
        return names, "certspotter"


class SmuggleTool(Tool):
    name = "smuggle"
    description = "HTTP request smuggling CLUE: divergensi timing CL.TE/TE.CL terkontrol."
    risk_tags = {"active"}
    source_skill = "t2-medium-01"

    def _raw_roundtrip(self, host: str, port: int, use_tls: bool, raw: bytes,
                       timeout: float) -> tuple[bool, str]:
        """Kirim request mentah; return (berhasil_respons, status_line/waktu).
        (True, line) = respons datang; (False, '') = timeout/tutup tanpa respons."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                sslctx = ssl.create_default_context()
                sslctx.check_hostname = False
                sslctx.verify_mode = ssl.CERT_NONE
                sock = sslctx.wrap_socket(sock)
            sock.settimeout(timeout)
            sock.sendall(raw)
            try:
                resp = sock.recv(1024).decode("latin-1", "replace")
            except (socket.timeout, TimeoutError):
                sock.close()
                return False, ""
            sock.close()
            if not resp:
                return False, ""
            return True, resp.split("\r\n", 1)[0]
        except OSError:
            return False, ""

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        parts = urlsplit(url)
        use_tls = parts.scheme == "https"
        host = parts.hostname or "127.0.0.1"
        port = parts.port or (443 if use_tls else 80)
        probe_timeout = min(ctx.timeout_s, 4.0)
        findings: list[Finding] = []
        ctx.throttle()
        # Baseline wajib cepat — kalau baseline saja lambat, uji timing tidak sah
        baseline = self._raw_roundtrip(
            host, port, use_tls,
            b"POST / HTTP/1.1\r\nHost: " + host.encode() +
            b"\r\nContent-Length: 5\r\nContent-Type: application/x-www-form-urlencoded"
            b"\r\nConnection: close\r\n\r\nx=1&y", probe_timeout)
        ctx.world.request_count += 1
        if not baseline[0]:
            ctx.world.note("smuggle: baseline gagal/tidak respons — target di-skip")
            return ToolResult(tool=self.name, ok=True, data={"baseline": "fail"})

        def dual_probe(body: bytes, cl: int) -> bool:
            head = (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {cl}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Connection: close\r\n\r\n").encode("latin-1")
            raw = head + body
            ctx.throttle()
            ok, _line = self._raw_roundtrip(host, port, use_tls, raw, probe_timeout)
            ctx.world.request_count += 1
            return not ok  # True = timeout (divergensi)

        clte = dual_probe(b"1\r\nZ\r\nQ\r\n", 4)      # front CL / back TE: back-end menunggu
        clte2 = dual_probe(b"1\r\nZ\r\nQ\r\n", 4) if clte else False
        tecl = dual_probe(b"0\r\n\r\nX", 6)            # front TE / back CL: sisa body tersangkut
        tecl2 = dual_probe(b"0\r\n\r\nX", 6) if tecl else False
        ctx.world.note(f"smuggle: CL.TE={clte}/{clte2} TE.CL={tecl}/{tecl2} (baseline cepat)")

        variant, hits = "", 0
        if clte and clte2:
            variant, hits = "CL.TE", 2
        elif tecl and tecl2:
            variant, hits = "TE.CL", 2
        elif clte or tecl:
            variant, hits = ("CL.TE" if clte else "TE.CL"), 1
        if variant:
            strict = hits == 2
            findings.append(Finding(
                tool=self.name,
                title=f"HTTP request smuggling clue ({variant} timing divergence)",
                severity="medium", cwe="CWE-444",
                description=(f"Request dengan Content-Length + Transfer-Encoding ganda menimbulkan "
                             f"divergensi timing {variant} konsisten {hits}x terhadap {host} "
                             f"(baseline merespons cepat; probe probe_timeout={probe_timeout}s). "
                             + ("Ini kuat dugaan desync front-end/back-end." if strict else
                                "Sinyal tunggal — butuh konfirmasi manual (ladder duplikasi) "
                                "sebelum diklaim bisa dieksploitasi.")),
                recommendation="Tolak/normalisasi header CL+TE ganda di edge; samakan parser "
                               "front-end dan back-end; matikan reuse koneksi antar layer.",
                target_url=url, request=f"POST / (CL+TE dual, body {variant})",
                response=f"baseline=fast; {variant} timeout {hits}/2",
                confidence=0.6 if strict else 0.3,
                source_skill=self.source_skill,
                status="confirmed" if strict else "unconfirmed",
                evidence_kind="probe-pair"))
        return ToolResult(tool=self.name, ok=True, data={"variant": variant}, findings=findings)


class CacheDecTool(Tool):
    name = "cache_dec"
    description = "Web cache deception: path + '.css' menyajikan data akun."
    risk_tags = {"active"}
    source_skill = "t2-medium-02"

    PROTECTED = ("profile", "account", "settings", "dashboard", "orders", "billing",
                 "member", "my/", "my-", "/me", "user")

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 12))
        candidates = []
        for ep in ctx.world.endpoints.values():
            if len(candidates) >= 4:
                break
            path = urlsplit(ep.url).path
            if (ep.status == 200 and path and path not in candidates
                    and any(k in path.lower() for k in self.PROTECTED)):
                candidates.append(path)
        findings: list[Finding] = []
        tested = 0
        for path in candidates:
            if tested + 3 > cap or ctx.world.request_count >= ctx.max_requests:
                break
            plain_url = urljoin(base + "/", path.lstrip("/"))
            css_url = plain_url + ".css"
            try:
                ctx.throttle()
                sp, hp, bp, _m = http_engine.http_get(plain_url, timeout=ctx.timeout_s)
                ctx.world.observe_response(plain_url, sp, hp, bp, self.name)
                ctx.throttle()
                sc, hc, bc, _m = http_engine.http_get(css_url, timeout=ctx.timeout_s,
                                                      follow_redirects=False)
                ctx.world.observe_response(css_url, sc, hc, bc, self.name)
                ctx.throttle()
                sn, hn, bn, _m = http_engine.http_get(
                    urljoin(base + "/", f"cyphron-notfound-{int(time.time())}.css"),
                    timeout=ctx.timeout_s)
                tested += 3
            except Exception:
                continue
            if sp != 200 or sc != 200:
                continue
            body_html = "<html" in (bc or "").lower() or "<body" in (bc or "").lower()
            ctype_html = "html" in _hdr(hc, "content-type").lower()
            sim_plain = difflib.SequenceMatcher(None, bc or "", bp or "").ratio()
            sim_404 = difflib.SequenceMatcher(None, bc or "", bn or "").ratio()
            # FP-guard: .css mirip halaman akun, JAUH lebih mirip dari body 404,
            # dan bentuknya halaman (bukan stylesheet/error generik)
            if (sim_plain >= 0.6 and sim_plain > sim_404 and body_html and ctype_html):
                findings.append(Finding(
                    tool=self.name,
                    title=f"Cache deception: {path}.css menyajikan isi {path}",
                    severity="medium", cwe="CWE-525",
                    description=(f"Permintaan {css_url} (ekstensi statis) mengembalikan halaman "
                                 f"akun yang sama dengan {plain_url} (kemiripan {sim_plain:.0%}, "
                                 f"vs {sim_404:.0%} terhadap 404). Web cache bisa menyimpan halaman "
                                 f"terautentikasi di bawah kunci statis dan menyajikannya ke pihak lain."),
                    recommendation="Terapkan cache rule berbasis path asli (bukan ekstensi); "
                                   "Pastikan Cache-Control: no-store pada respons terautentikasi.",
                    target_url=css_url, request=f"GET {css_url}",
                    response=f"status={sc}; sim(akun)={sim_plain:.2f}; sim(404)={sim_404:.2f}",
                    poc=f"curl -s '{css_url}' | head -c 200",
                    confidence=0.85, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="probe-pair"))
        ctx.world.note(f"cache_dec: {len(candidates)} kandidat, {tested} request, "
                       f"{len(findings)} hit")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class OAuthTool(Tool):
    name = "oauth"
    description = "Audit endpoint authorize: state hilang, redirect_uri longgar, nonce OIDC."
    risk_tags = {"active"}
    source_skill = "t2-medium-03"

    DEFAULT_PATHS = ("/oauth/authorize", "/authorize", "/oauth2/authorize", "/auth/authorize")

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 12))
        paths: list[str] = []
        for ep in ctx.world.endpoints.values():
            p = urlsplit(ep.url).path.lower()
            if ("authoriz" in p or "oauth" in p) and p not in paths:
                paths.append(p)
        for p in self.DEFAULT_PATHS:
            if len(paths) >= 4:
                break
            if p not in paths:
                paths.append(p)
        paths = paths[:4]
        findings: list[Finding] = []
        tested = 0
        for path in paths:
            if tested + 3 > cap or ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                s0, h0, b0, _m = http_engine.http_get(urljoin(base, path), timeout=ctx.timeout_s,
                                                      follow_redirects=False)
                ctx.world.observe_response(urljoin(base, path), s0, h0, b0, self.name)
                tested += 1
            except Exception:
                continue
            if s0 in (404, 405, 410):
                continue
            # Probe A: response_type=code TANPA state, redirect_uri canary
            probe = (f"{urljoin(base, path)}?client_id=cyphron-probe&response_type=code"
                     f"&redirect_uri={quote(_CANARY, safe='')}")
            try:
                ctx.throttle()
                sa, ha, ba, _m = http_engine.http_get(probe, timeout=ctx.timeout_s,
                                                      follow_redirects=False)
            except Exception:
                continue
            ctx.world.observe_response(probe, sa, ha, ba, self.name)
            tested += 1
            loc = _hdr(ha, "location")
            client_rejected = sa in (400, 401, 403)
            # FP-guard: server yang menolak client_id tak dikenal = validasi ketat,
            # bukan temuan; dan Location harus persis canary origin.
            if not client_rejected and loc.startswith(_CANARY_ORIGIN):
                if "code=" in loc:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"OAuth state tidak diwajibkan di {path}",
                        severity="medium", cwe="CWE-352",
                        description=(f"Endpoint {path} menerbitkan authorization code TANPA "
                                     f"parameter state (302 -> canary). Flow OAuth tanpa state "
                                     f"membuka CSRF login / code injection."),
                        recommendation="Wajibkan state per-request dan validasi di callback.",
                        target_url=urljoin(base, path), request=f"GET {path}?...&response_type=code (tanpa state)",
                        response=f"{sa} Location: {loc[:160]}",
                        poc=probe, confidence=0.7, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response"))
                findings.append(Finding(
                    tool=self.name,
                    title=f"redirect_uri diterima untuk host arbitrer di {path}",
                    severity="medium", cwe="CWE-601",
                    description=(f"{path} menerima redirect_uri ke { _CANARY_ORIGIN } (host "
                                 f"kontrol peneliti) dan me-redirect ke sana. Validasi "
                                 f"redirect_uri tidak ketat -> code bisa dialihkan."),
                    recommendation="Whitelist exact-match redirect_uri per client; tolak path/"
                                   "suffix arbitrer.",
                    target_url=urljoin(base, path), request=f"GET {path}?...&redirect_uri={_CANARY}",
                    response=f"{sa} Location: {loc[:160]}",
                    poc=probe, confidence=0.85, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
            # Probe B: OIDC implicit response_type=id_token TANPA nonce
            probe_b = (f"{urljoin(base, path)}?client_id=cyphron-probe&response_type=id_token"
                       f"&scope=openid&redirect_uri={quote(_CANARY, safe='')}")
            try:
                ctx.throttle()
                sb, hb, bb, _m = http_engine.http_get(probe_b, timeout=ctx.timeout_s,
                                                      follow_redirects=False)
            except Exception:
                continue
            ctx.world.observe_response(probe_b, sb, hb, bb, self.name)
            tested += 1
            locb = _hdr(hb, "location")
            if (sb not in (400, 401, 403) and locb.startswith(_CANARY_ORIGIN)
                    and "id_token=" in locb and locb.split("id_token=", 1)[1].count(".") >= 2):
                findings.append(Finding(
                    tool=self.name,
                    title=f"OIDC nonce tidak diwajibkan di {path}",
                    severity="medium", cwe="CWE-346",
                    description=(f"Response type id_token diterbitkan tanpa nonce (302 -> canary "
                                 f"dengan id_token JWT). Tanpa binding nonce, id_token rentan "
                                 f"replay lintas flow."),
                    recommendation="Wajibkan dan validasi nonce di setiap implicit/hybrid flow.",
                    target_url=urljoin(base, path), request=f"GET {path}?...&response_type=id_token (tanpa nonce)",
                    response=f"{sb} Location: {locb[:160]}",
                    poc=probe_b, confidence=0.8, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
        ctx.world.note(f"oauth: {tested} request pada {len(paths)} kandidat path, "
                       f"{len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class PuzzleTool(Tool):
    name = "puzzle"
    description = "Session puzzling / type confusion: password string vs array."
    risk_tags = {"active"}
    source_skill = "t2-medium-06"

    _SUCCESS_RE = re.compile(
        r"(?i)(welcome|dashboard|logout|sign\s?out|my\s?account|akun\s?anda|selamat\s?datang)")

    def _is_success(self, status: int, body: str, location: str) -> bool:
        if status in (301, 302, 303, 307) and location:
            return not any(k in location.lower() for k in ("login", "signin", "masuk", "error"))
        return bool(self._SUCCESS_RE.search(body or ""))

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 6))
        # 1) temukan form login (endpoint dengan field password, atau path umum)
        forms: list[tuple[str, str]] = []
        for ep in ctx.world.endpoints.values():
            if len(forms) >= 1:
                break
            fields = ep.form_fields or []
            if any("password" in f.lower() for f in fields):
                forms.append((ep.url, next((f for f in fields if "password" not in f.lower()),
                                           "email")))
        if not forms:
            for path in ("/login", "/signin", "/auth/login"):
                try:
                    ctx.throttle()
                    st, hd, bd, _m = http_engine.http_get(urljoin(base, path), timeout=ctx.timeout_s)
                    ctx.world.observe_response(urljoin(base, path), st, hd, bd, self.name)
                except Exception:
                    continue
                from .crawler import _PageParser
                parser = _PageParser()
                parser.feed(bd or "")
                for form in parser.forms:
                    if any("password" in f.lower() for f in form["fields"]):
                        user_key = next((f for f in form["fields"]
                                         if "password" not in f.lower()), "email")
                        user_key = "email" if user_key.startswith("input[type=") else user_key
                        forms.append((urljoin(urljoin(base, path), form["action"] or path), user_key))
                        break
                if forms:
                    break
        if not forms or ctx.world.request_count >= ctx.max_requests:
            ctx.world.note("puzzle: tidak ada form login yang teramati")
            return ToolResult(tool=self.name, ok=True, data={"forms": 0})
        login_url, user_key = forms[0]
        findings: list[Finding] = []
        tested = 0
        wrong = "cyphron-wrong-pass-9f3x"

        def post(fields: dict) -> tuple[int, str, str]:
            nonlocal tested
            ctx.throttle()
            st, hd, bd, _m = http_engine.http_get(
                login_url, timeout=ctx.timeout_s, method="POST",
                data=urlencode(fields).encode(), follow_redirects=False,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            ctx.world.observe_response(login_url, st, hd, bd, self.name)
            tested += 1
            return st, bd or "", _hdr(hd, "location")

        # Baseline: password salah HARUS gagal
        s_base, b_base, l_base = post({user_key: "cyphron-probe@example.test", "password": wrong})
        base_failed = not self._is_success(s_base, b_base, l_base)
        if base_failed and tested < cap:
            # Tipe array: password[]=wrong (parser PHP/Node yang bingung tipe)
            s_arr, b_arr, l_arr = post({f"{user_key}": "cyphron-probe@example.test",
                                        "password[]": wrong})
            # Parameter ganda: dua password salah berbeda
            s_dup, b_dup, l_dup = post(
                [(user_key, "cyphron-probe@example.test"), ("password", wrong),
                 ("password", "cyphron-wrong-pass-77a")] if tested < cap else
                [(user_key, "cyphron-probe@example.test"), ("password", wrong)])
        else:
            s_arr = s_dup = 0
            b_arr = b_dup = l_arr = l_dup = ""
        hits = []
        if base_failed and self._is_success(s_arr, b_arr, l_arr):
            hits.append(("array (password[])", s_arr))
        elif base_failed and self._is_success(s_dup, b_dup, l_dup):
            hits.append(("duplicate param", s_dup))
        if hits:
            variant, status = hits[0]
            findings.append(Finding(
                tool=self.name,
                title=f"Session puzzling / type confusion pada login ({variant})",
                severity="medium", cwe="CWE-384",
                description=(f"Baseline password salah ditolak di {login_url}, tetapi varian "
                             f"'{variant}' dengan password SALAH diproses sebagai login sukses "
                             f"(status {status}). Parser parameter menangani tipe string/array "
                             f"secara tidak konsisten -> auth lolos via tipe."),
                recommendation="Kanonisasi parameter (ambil satu nilai, tolak tipe array); "
                               "validasi tipe eksplisit sebelum membandingkan kredensial.",
                target_url=login_url, request=f"POST {login_url} (password[] salah)",
                response=f"baseline=fail; {variant}={status}",
                confidence=0.8, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-pair"))
        ctx.world.note(f"puzzle: {tested} request pada {login_url}, {len(findings)} hit")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class JsonInjTool(Tool):
    name = "json_inj"
    description = "JSON injection: kunci baru terverifikasi muncul di respons."
    risk_tags = {"active"}
    source_skill = "t2-medium-07"

    PAYLOADS = (
        'x","injected_key":"' + _MARKER,     # breaker double-quote
        "x','injected_key':'" + _MARKER,     # single-quote (template JS/Python)
        'x\\",\\"injected_key\\":\\"' + _MARKER,  # escaped-quote (Jackson/string-escape)
    )

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 12))
        findings: list[Finding] = []
        tested = 0
        hit_params: set[tuple[str, str]] = set()
        for ep in ctx.world.param_endpoints(limit=8):
            if tested >= cap or ctx.world.request_count >= ctx.max_requests:
                break
            probe_url = ep.url.split("?", 1)[0]
            for param in ep.params[:2]:
                if tested + 2 > cap:
                    break
                try:
                    ctx.throttle()
                    sb, hb, bb, _m = http_engine.http_get(
                        f"{probe_url}?{urlencode({param: 'cyphron-baseline'})}",
                        timeout=ctx.timeout_s)
                    ctx.world.observe_response(f"{probe_url}?{param}=baseline", sb, hb, bb, self.name)
                except Exception:
                    continue
                tested += 1
                if sb != 200 or _MARKER in (bb or ""):
                    continue
                for payload in self.PAYLOADS:
                    if tested + 1 > cap:
                        break
                    try:
                        ctx.throttle()
                        st, ht, bt, _m = http_engine.http_get(
                            f"{probe_url}?{urlencode({param: payload})}", timeout=ctx.timeout_s)
                    except Exception:
                        continue
                    ctx.world.observe_response(f"{probe_url}?{param}=<payload>", st, ht, bt, self.name)
                    tested += 1
                    key, val = "injected_key", _MARKER
                    if _json_key_injected(bt or ""):
                        if (probe_url, param) not in hit_params:
                            hit_params.add((probe_url, param))
                            findings.append(Finding(
                                tool=self.name,
                                title=f"JSON injection terkonfirmasi pada param '{param}'",
                                severity="medium", cwe="CWE-943",
                                description=(f"Nilai '{param}' digabung mentah ke struktur JSON "
                                             f"oleh {probe_url}: kunci 'injected_key' dengan "
                                             f"marker unik muncul di respons, sementara baseline "
                                             f"tanpa marker. Struktur JSON berubah terverifikasi."),
                                recommendation="Serialisasi via library JSON (bukan string concat); "
                                               "escape/validasi input sebelum membentuk JSON.",
                                target_url=probe_url, param=param,
                                request=f"GET {probe_url}?{param}=<breaker>",
                                response=f"injected_key={_MARKER} hadir; baseline tidak",
                                poc=f"curl -s '{probe_url}?{param}={quote(self.PAYLOADS[0])}'",
                                confidence=0.9, source_skill=self.source_skill,
                                status="confirmed", evidence_kind="request-response"))
                        break
                    elif st >= 500 and sb == 200 and any(
                            k in (bt or "").lower() for k in ("json", "parse", "unexpected", "token")):
                        if (probe_url, param) not in hit_params:
                            hit_params.add((probe_url, param))
                            findings.append(Finding(
                                tool=self.name,
                                title=f"Dugaan JSON injection (500 parse error) pada '{param}'",
                                severity="low", cwe="CWE-943",
                                description=(f"Payload breaker JSON membuat {probe_url} berubah "
                                             f"200->500 dengan pesan parser JSON. Input masuk ke "
                                             f"struktur JSON; verifikasi manual apakah kunci bisa "
                                             f"disuntikkan."),
                                recommendation="Serialisasi via library JSON; jangan concat string.",
                                target_url=probe_url, param=param,
                                request=f"GET {probe_url}?{param}=<breaker>",
                                response=f"{sb}->{st}; body: {(bt or '')[:160]}",
                                confidence=0.3, source_skill=self.source_skill,
                                status="unconfirmed", evidence_kind="request-response"))
                        break
        ctx.world.note(f"json_inj: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)
