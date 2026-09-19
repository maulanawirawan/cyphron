"""business_logic — Mesin Alasan Logika Bisnis IDENTITY x OBJECT x ACTION x
STATE (Unity U5).

Model mesin-keadaan bawaan (tabel deterministik, tanpa LLM): order, refund,
coupon, account, approval. Validator memeriksa transisi yang DIAMATI
(capture sesi berotorisasi milik operator: dari browser_scout, log, atau
berkas JSON yang disiapkan engagement):

  transisi ilegal   : (from, to) tidak ada di tabel legal padahal KEDUA
                      keadaan dikenal model (mis. CANCELLED -> APPROVED,
                      REJECTED -> APPROVED);
  aksi berulang     : (object_id, action) sama mencapai keadaan terminal
                      dua kali (refund ganda, coupon reuse).

Zero-FP: keadaan/tipe objek yang TIDAK dikenal diabaikan (fail-open terhadap
model baru, fail-closed terhadap pelanggaran yang dikenal); temuan butuh
bukti transisi yang terekam — satu rekaman = LEAD (unconfirmed), rekaman
berganda = weakness terkonfirmasi. Engine TIDAK PERNAH memicu aksi state-
changing ke target; ia hanya memvalidasi transisi yang sudah terekam.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

# ------------------------------------------------------------- model tabel
_MODELS: dict[str, dict] = {
    "order": {
        "states": {"draft", "placed", "paid", "shipped", "delivered",
                   "cancelled", "refunded"},
        "legal": {("draft", "placed"), ("placed", "paid"), ("paid", "shipped"),
                  ("shipped", "delivered"), ("draft", "cancelled"),
                  ("placed", "cancelled"), ("paid", "cancelled"),
                  ("paid", "refunded"), ("shipped", "refunded"),
                  ("delivered", "refunded")},
        "terminal": {"delivered", "cancelled", "refunded"},
    },
    "refund": {
        "states": {"none", "requested", "approved", "rejected", "refunded"},
        "legal": {("none", "requested"), ("requested", "approved"),
                  ("requested", "rejected"), ("approved", "refunded")},
        "terminal": {"refunded", "rejected"},
    },
    "coupon": {
        "states": {"unused", "used", "expired"},
        "legal": {("unused", "used"), ("unused", "expired")},
        "terminal": {"used", "expired"},
    },
    "account": {
        "states": {"pending", "active", "suspended", "closed"},
        "legal": {("pending", "active"), ("active", "suspended"),
                  ("suspended", "active"), ("active", "closed")},
        "terminal": {"closed"},
    },
    "approval": {
        "states": {"draft", "submitted", "approved", "rejected", "cancelled"},
        "legal": {("draft", "submitted"), ("submitted", "approved"),
                  ("submitted", "rejected"), ("draft", "cancelled"),
                  ("submitted", "cancelled")},
        "terminal": {"approved", "rejected", "cancelled"},
    },
}

_ALIASES = {
    "canceled": "cancelled", "void": "cancelled", "voided": "cancelled",
    "redeemed": "used", "complete": "delivered", "completed": "delivered",
    "confirmed": "approved", "approve": "approved", "cancel": "cancelled",
    "request": "requested", "submit": "submitted", "reject": "rejected",
}

# kata kunci -> model (untuk inferensi tipe objek dari action/endpoint)
_TYPE_HINTS = [
    (("refund", "retur"), "refund"),
    (("coupon", "voucher", "promo", "redeem"), "coupon"),
    (("order", "invoice", "cart", "checkout"), "order"),
    (("approve", "approval", "submission", "document", "permit"), "approval"),
    (("account", "user", "suspend"), "account"),
]


def normalize_state(s: str) -> str:
    s = str(s or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _ALIASES.get(s, s)


def infer_model(text: str) -> str | None:
    t = str(text or "").lower()
    for keys, model in _TYPE_HINTS:
        if any(k in t for k in keys):
            return model
    return None


def is_known(model: str, state: str) -> bool:
    m = _MODELS.get(model)
    return bool(m) and state in m["states"]


def is_legal(model: str, frm: str, to: str) -> bool:
    m = _MODELS.get(model)
    if not m:
        return True  # model tak dikenal: fail-open (bukan klaim)
    return (frm, to) in m["legal"]


def validate_transitions(observations: list[dict]) -> list[dict]:
    """Validasi murni (tanpa I/O): kembalikan daftar pelanggaran.

    Setiap baris masukan: {object_type?, object_id, action, from_state,
    to_state, identity?, source?}. Keluaran: {kind: "illegal-transition"|
    "repeated-terminal", model, object_id, action, from_state, to_state,
    identity, count, records}."""
    violations: list[dict] = []
    terminal_hits: dict[tuple, list[dict]] = {}
    illegal_seen: dict[tuple, list[dict]] = {}

    for obs in observations or []:
        if not isinstance(obs, dict):
            continue
        action = str(obs.get("action", "")).strip().lower()
        object_id = str(obs.get("object_id", "")).strip()
        if not action or not object_id:
            continue
        model = str(obs.get("object_type", "")).lower() or None
        if model not in _MODELS:
            model = infer_model(f"{action} {obs.get('endpoint', '')} "
                                f"{obs.get('object_type', '')}")
        if model not in _MODELS:
            continue
        frm = normalize_state(obs.get("from_state", ""))
        to = normalize_state(obs.get("to_state", ""))
        if not frm or not to:
            continue
        if not (is_known(model, frm) and is_known(model, to)):
            continue  # fail-open: keadaan di luar model bukan klaim
        rec = {**obs, "model": model, "from_state": frm, "to_state": to}

        if not is_legal(model, frm, to):
            key = (model, frm, to)
            illegal_seen.setdefault(key, []).append(rec)
        m = _MODELS[model]
        if to in m["terminal"]:
            terminal_hits.setdefault((object_id, action), []).append(rec)

    for (model, frm, to), recs in sorted(illegal_seen.items()):
        violations.append({
            "kind": "illegal-transition", "model": model,
            "from_state": frm, "to_state": to,
            "action": str(recs[0].get("action", "")),
            "identity": str(recs[0].get("identity", "")),
            "object_id": str(recs[0].get("object_id", "")),
            "count": len(recs), "records": recs,
        })
    for (object_id, action), recs in sorted(terminal_hits.items()):
        if len(recs) < 2:
            continue
        model = recs[0]["model"]
        violations.append({
            "kind": "repeated-terminal", "model": model,
            "from_state": recs[1]["from_state"],
            "to_state": recs[1]["to_state"],
            "identity": str(recs[1].get("identity", "")),
            "object_id": object_id, "action": action,
            "count": len(recs), "records": recs,
        })
    return violations


def _finding_for(v: dict, attested: bool) -> Finding:
    kind = v["kind"]
    if kind == "illegal-transition":
        title = (f"Transisi ilegal {v['model'].upper()}: "
                 f"{v['from_state'].upper()} -> {v['to_state'].upper()}")
        desc = (f"Alur logika bisnis {v['model']}: keadaan "
                f"'{v['from_state']}' tidak boleh berpindah ke "
                f"'{v['to_state']}' (tabel legalitas model). Transisi "
                f"teramati {v['count']}x pada objek '{v['object_id']}' "
                f"(identitas: {v['identity'] or '-'}). Validator "
                f"deterministik; bukti = rekaman transisi yang terekam "
                f"dari sesi berotorisasi.")
        sev = "high"
    else:
        title = (f"Aksi '{v['action']}' berulang hingga status terminal "
                 f"pada objek '{v['object_id']}'")
        desc = (f"Objek '{v['object_id']}' menerima aksi '{v['action']}' "
                f"hingga keadaan terminal '{v['to_state']}' sebanyak "
                f"{v['count']} kali (model {v['model']}; identitas: "
                f"{v['identity'] or '-'}). Pola ini cocok dengan defect "
                f"logika bisnis: aksi tunggal-use dieksekusi berulang "
                f"(refund ganda / coupon reuse / approval ganda).")
        sev = "high"
    confirmed = attested or v["count"] >= 2
    f = Finding(
        tool="business_logic",
        title=title,
        severity=sev,
        description=desc,
        recommendation=(
            "Tegakkan state machine di sisi server (tolak transisi di luar "
            "tabel legal) dan idempotensi aksi (idempotency-key / cek "
            "keadaan terminal sebelum eksekusi)."),
        cwe="CWE-840" if kind == "illegal-transition" else "CWE-841",
        confidence=0.85 if confirmed else 0.4,
        finding_class="weakness",
        status="confirmed" if confirmed else "unconfirmed",
        evidence_kind="arithmetic" if confirmed else "",
    )
    f.attach_evidence("transition-records", {
        "kind": kind, "model": v["model"], "count": v["count"],
        "objects": sorted({str(r.get("object_id", "")) for r in v["records"]}),
    })
    return f


class BusinessLogicTool(Tool):
    name = "business_logic"
    description = ("Logika bisnis IDENTITY x OBJECT x ACTION x STATE: "
                   "validasi transisi teramati vs tabel legalitas (tanpa "
                   "request state-changing).")
    risk_tags = {"passive"}
    source_skill = "t2-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        observations: list[dict] = list(args.get("observations") or [])
        src = str(args.get("observations_file") or "").strip()
        if src and not observations:
            try:
                loaded = json.loads(Path(src).read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    observations = [o for o in loaded if isinstance(o, dict)]
            except (OSError, ValueError) as exc:
                ctx.world.note(f"business_logic: observations_file gagal: {exc}")

        if not observations:
            # deteksi permukaan state-machine (LEAD pasif, tanpa request)
            hints = ("coupon", "voucher", "promo", "redeem", "refund",
                     "order", "invoice", "status", "state", "approve")
            found = sorted({p for ep in ctx.world.param_endpoints(limit=25)
                            for p in ep.params if p.lower() in hints})
            if found:
                f = Finding(
                    tool=self.name,
                    title=("Permukaan mesin-keadaan terdeteksi: parameter "
                           + ", ".join(found)),
                    severity="info",
                    description=(
                        "Parameter berbau logika bisnis teramati di world "
                        "model. Validasi transisi membutuhkan capture "
                        "transisi nyata (observations JSON) dari sesi uji "
                        "berotorisasi — tanpa itu ini LEAD, bukan temuan."),
                    recommendation=(
                        "Rekam transisi nyata (object/action/from/to) dari "
                        "sesi uji, lalu jalankan engine ini dengan "
                        "--observations untuk validasi illegal transition."),
                    confidence=0.3,
                    finding_class="info",
                    status="unconfirmed",
                )
                ctx.world.note("business_logic: permukaan state-machine "
                               f"terdeteksi ({', '.join(found)}) — LEAD")
                return ToolResult(tool=self.name, ok=True,
                                  data={"surfaces": found},
                                  findings=[f])
            return ToolResult(tool=self.name, ok=True,
                              data={"surfaces": [], "violations": 0})

        violations = validate_transitions(observations)
        # satu defect per (model, object, aksi): illegal-transition menang
        # atas repeated-terminal bila keduanya menunjuk rekaman yang sama
        seen: set[tuple] = set()
        deduped: list[dict] = []
        for v in sorted(violations,
                        key=lambda x: 0 if x["kind"] == "illegal-transition"
                        else 1):
            key = (v.get("model"), v.get("object_id"), v.get("action") or "")
            if key in seen:
                continue
            seen.add(key)
            deduped.append(v)
        violations = deduped
        findings = [_finding_for(v, bool(args.get("attested")))
                    for v in violations]
        ctx.world.note(
            f"business_logic: {len(observations)} transisi divalidasi -> "
            f"{len(violations)} pelanggaran tabel legalitas")
        return ToolResult(tool=self.name, ok=True,
                          data={"validated": len(observations),
                                "violations": len(violations),
                                "details": [
                                    {k: v[k] for k in
                                     ("kind", "model", "from_state",
                                      "to_state", "count")
                                     if k in v}
                                    for v in violations]},
                          findings=findings)
