"""deser_probe — insecure deserialization marker + gadget OOB confirm
(CWE-502, medium->critical).

Dua tingkat bukti:
  1. ERROR-SIGNATURE (default): canary serialized ringan (PHP stdClass,
     Java stream header, Python pickle header) dikirim ke endpoint; bila
     respons memuat signature error deserialisasi yang TIDAK ada di
     baseline (junk body) -> deserialisasi aktif terbukti (medium;
     evidence_kind request-pair). Canary TIDAK berisi gadget — tidak ada
     eksekusi.
  2. GADGET OOB (args.payload_b64 + args.oob_check_url): payload gadget
     MILIK PENELITI (mis. ysoserial URLDNS yang hanya resolve DNS) dikirim
     verbatim; konfirmasi HANYA via capture OOB (reuse pola ssrf_oob) ->
     critical confirmed. Tanpa OOB = tetap lead.

FP-guard: junk baseline wajib; signature harus beda dari baseline; canary
harus benar-benar terkirim (status dicatat); cease-on-data (stop di bukti
pertama); maks 6 request.
"""

from __future__ import annotations

import base64
import binascii
import json

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_DESER_ERROR_SIGS = (
    "unserialize():",          # PHP
    "ObjectInputStream",       # Java
    "java.io.InvalidClassException",
    "java.io.StreamCorruptedException",
    "StreamCorrupted",
    "UnpicklingError",         # Python pickle
    "pickle.Unpickling",
    "deserialization error",   # umum
    "SerializationException",  # umum / .NET & Java wrapper
)

# canary: TIDAK berisi gadget; cukup memicu parser error channel
CANARIES: list[tuple[str, bytes]] = [
    ("php-stdClass", b'O:8:"stdClass":0:{}'),
    ("java-stream-header", b"\xac\xed\x00\x05"),
    ("python-pickle-header", b"\x80\x04\x95\x00"),
]


class DeserProbeTool(Tool):
    name = "deser_probe"
    description = ("Insecure deserialization: canary error-signature (tanpa "
                   "gadget) + konfirmasi gadget OOB via payload peneliti.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        content_type = str(args.get("content_type") or "application/octet-stream")
        payload_b64 = str(args.get("payload_b64") or "").strip()
        oob_check = str(args.get("oob_check_url") or "").strip()
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")

        def post(body: bytes):
            ctx.throttle()
            st, _h, txt, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, method="POST", data=body,
                headers={"Content-Type": content_type})
            ctx.world.request_count += 1
            return st, txt.lower()

        # ---- baseline: junk body (harus TIDAK memuat signature)
        j_st, j_body = post(b"cyphron-junk-not-serialized")
        data: dict = {"baseline_status": j_st, "canaries": [], "mode": []}

        findings: list[Finding] = []
        sig_hit = None
        for name, blob in CANARIES:
            if ctx.world.request_count >= ctx.max_requests or sig_hit:
                break  # cease-on-data
            st, body = post(blob)
            sigs = [s for s in _DESER_ERROR_SIGS if s.lower() in body]
            data["canaries"].append({"canary": name, "status": st,
                                     "signatures": sigs})
            if sigs and not any(s.lower() in j_body for s in sigs):
                sig_hit = (name, st, sigs)
        if sig_hit:
            name, st, sigs = sig_hit
            data["mode"].append("error-signature")
            findings.append(Finding(
                tool=self.name,
                title=f"Deserialization endpoint confirmed via error signature "
                      f"({name})",
                severity="medium", cwe="CWE-502",
                description=(
                    f"Endpoint {url} memproses data serialized: canary tanpa "
                    f"gadget '{name}' memicu signature error deserialisasi "
                    f"({', '.join(sigs)}) yang TIDAK ada pada baseline junk. "
                    f"Channel error memaparkan parser deserialisasi -> target "
                    f"gadget chain (mis. ysoserial) layak dievaluasi OLEH "
                    f"PENELITI dengan payload pingback-nya sendiri. cease-on-"
                    f"data: canary ini tidak mengeksekusi apa pun."),
                recommendation=(
                    "Jangan deserialisasi data tak terpercaya; gunakan format "
                    "data polos (JSON) dengan schema; bila perlu, allowlist "
                    "class dan sembunyikan channel error."),
                target_url=url,
                request=f"POST {url} [{content_type}] <canary {name}>",
                response=f"status={st}; signatures={sigs} (tidak ada di baseline)",
                confidence=0.6, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-pair"))

        # ---- gadget OOB (payload milik peneliti)
        if payload_b64 and not findings:
            try:
                gadget = base64.b64decode(payload_b64, validate=True)
            except (binascii.Error, ValueError):
                return ToolResult(tool=self.name, ok=False,
                                  error="payload_b64 bukan base64 valid")
            g_st, _b = post(gadget)
            data["gadget_sent"] = {"status": g_st, "bytes": len(gadget)}
            data["mode"].append("gadget-oob")
            if not oob_check:
                data["lead"] = ("gadget terkirim; sediakan oob_check_url "
                                "untuk konfirmasi out-of-band")
            else:
                try:
                    ctx.throttle()
                    st, _h, body, _ms = http_engine.http_get(
                        oob_check, timeout=ctx.timeout_s)
                    ctx.world.request_count += 1
                    hits = json.loads(body or "{}")
                    count = int(hits.get("count")
                                or len(hits.get("data") or []) or 0)
                except Exception as e:
                    data["oob_check_error"] = type(e).__name__
                    count = 0
                data["oob_capture_count"] = count
                if count > 0:
                    findings.append(Finding(
                        tool=self.name,
                        title="Insecure deserialization gadget confirmed "
                              "out-of-band",
                        severity="critical", cwe="CWE-502",
                        description=(
                            f"Payload gadget peneliti ({len(gadget)} bytes) "
                            f"diproses server dan memicu koneksi keluar — "
                            f"terbukti lewat capture OOB ({count} hit). "
                            f"Deserialisasi tak terpercaya = eksekusi kode "
                            f"kelas tinggi. cease-on-data: hanya payload "
                            f"pingback, tidak ada gadget destruktif/ekstraksi."),
                        recommendation=(
                            "Larang deserialisasi input tak terpercaya; "
                            "pindah ke format polos; filter channel gadget "
                            "di library; monitor koneksi keluar anomali."),
                        target_url=url,
                        request=f"POST {url} [{content_type}] <gadget b64 "
                                f"{len(gadget)} bytes>",
                        response=f"OOB capture: {count} hit",
                        confidence=1.0, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="probe-pair"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
