"""[F29] Attack planner — fase 2 exploit tier (docs/EXPLOIT-TIER.md).

Menyusun attack-plan.json DINAMIS di atas playbook registry yang ada
(tools/exploit_playbooks.py) dari lead recon (findings.json tier0).

BATAS KERAS (fail-closed, docs/EXPLOIT-TIER.md):
  1. Planner TIDAK MENGEKSEKUSI apa pun — nol request ke target.
     Outputnya RENCANA; eksekusi tetap lewat exploit engine dengan
     gate yang sama (exploit_allowed).
  2. Config engine yang di-emit selalu "exploit_allowed": false —
     operator yang melipatnya secara sadar.
  3. LLM hanyalah PENYUSUN rencana dari menu playbook yang ada:
     tidak bisa menambah playbook baru, tidak bisa mengubah teknik,
     tidak bisa melewati never-list (dicek engine). Output LLM
     divalidasi skema; item invalid ditolak + tercatat.
  4. Inti DETERMINISTIK (default, tanpa LLM, tanpa request): mapping
     kategori lead -> playbook + parameter yang bisa diturunkan dari
     bukti. Parameter yang tidak derivable ditandai blocked=true
     (butuh operator), TIDAK dikarang.

Pemakaian:
  python tools/attack_planner.py --findings f.json --out plan.json
  python tools/attack_planner.py --findings f.json --out plan.json \
      --llm-url http://127.0.0.1:11434/v1/chat/completions \
      --llm-model llama3.1:8b --param idor-orders.other_id=1002
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import exploit_playbooks as ep  # noqa: E402

MAX_LEADS = 50

# ---- Spec parameter playbook: apa yang dibutuhkan, mana yang bisa
# diturunkan dari bukti. "operator" = butuh input operator (--param).
# path/param yang derivable diambil dari lead (target_url + extra.param).
PARAM_SPECS: dict[str, dict] = {
    "idor-orders": {"required": ["own_id", "other_id",
                                 "other_owner_email"],
                    "auto": {}},
    "admin-access": {"required": ["admin_path", "marker"],
                     "auto": {}},
    "sqli-products": {"required": ["path", "param", "baseline_value",
                                   "payload"],
                      "auto": {"path": "lead_path", "param": "lead_param"}},
    "ssrf-callback": {"required": ["path"],
                      "auto": {"path": "lead_path"},
                      "defaults": {"marker_host": "127.0.0.1"}},
    "jwt-weak-secret": {"required": [],
                        "defaults": {"token_path": "/api/token",
                                     "profile_path": "/api/profile"}},
    "jwt-alg-confusion": {"required": [],
                          "defaults": {"path": "/api/profile-loose",
                                       "strict_path": "/api/profile"}},
    "rce-marker": {"required": ["path"], "auto": {"path": "lead_path"},
                   "defaults": {"safe_path": "/api/ping-safe",
                                "param": "host"}},
    "upload-bypass": {"required": ["upload_path", "serve_prefix"],
                      "auto": {"upload_path": "lead_path"}},
    "race-coupon": {"required": [],
                    "defaults": {"redeem_path": "/api/coupon/redeem",
                                 "workers": 8}},
    "mass-assignment": {"required": [],
                        "defaults": {"update_path": "/api/profile/update",
                                     "token_path": "/api/token"}},
    "open-redirect": {"required": ["path"],
                      "auto": {"path": "lead_path"},
                      "defaults": {"param": "to",
                                   "external_url":
                                   "https://attacker.example/next"}},
    "xxe-callback": {"required": ["path"],
                     "auto": {"path": "lead_path"},
                     "defaults": {"marker_host": "127.0.0.1"}},
    "deser-rce": {"required": [],
                  "defaults": {"path": "/api/deser",
                               "marker_host": "127.0.0.1"}},
    "ssti-eval": {"required": ["path"], "auto": {"path": "lead_path"},
                  "defaults": {"param": "tpl"}},
    "lfi-traversal": {"required": ["path", "baseline_file",
                                   "traversal_payload", "canary_content"],
                      "auto": {"path": "lead_path"},
                      "defaults": {"param": "file"}},
    "nosqli-login": {"required": [],
                     "defaults": {"path": "/api/nosqli-login",
                                  "whoami_path": "/api/whoami"}},
    "crlf-inject": {"required": ["path"], "auto": {"path": "lead_path"},
                    "defaults": {"param": "text"}},
    "reset-enum": {"required": ["canary_email"],
                   "auto": {},
                   "defaults": {"path": "/api/reset"}},
    "xss-reflected": {"required": ["path"], "auto": {"path": "lead_path"},
                      "defaults": {"param": "q"}},
    "proto-pollution": {"required": [],
                        "defaults": {"merge_path": "/api/merge",
                                     "gadget_path": "/api/config"}},
    "jndi-oob": {"required": ["path"], "auto": {"path": "lead_path"},
                 "defaults": {"marker_host": "127.0.0.1"}},
    "cache-deception": {"required": [],
                        "defaults": {"path_prefix": "/cacheable/",
                                     "safe_prefix": "/cache-safe/"}},
    "host-header-poison": {"required": ["canary_email"],
                           "auto": {},
                           "defaults": {"path": "/api/forgot",
                                        "safe_path": "/api/forgot-safe",
                                        "check_path": "/api/reset-check",
                                        "poison_host":
                                        "attacker.example"}},
    "prompt-injection": {"required": ["path"], "auto": {},
                         "defaults": {"field": "message",
                                      "safe_path":
                                      "/api/llm-chat-safe"}},
    "llm-output": {"required": [], "auto": {},
                   "defaults": {"path": "/api/llm-render",
                                "field": "message",
                                "safe_path": "/api/llm-render-safe"}},
    "rag-poisoning": {"required": [], "auto": {},
                      "defaults": {"ingest_path": "/api/rag/ingest",
                                   "review_path":
                                   "/api/rag/ingest-review",
                                   "query_path": "/api/rag/query"}},
}

# ---- Mapping kategori lead -> kandidat playbook (deterministik)
CATEGORY_MAP = {
    "ACCESS-CONTROL": ["idor-orders", "admin-access", "mass-assignment"],
    "INJECTION": ["sqli-products", "ssti-eval", "lfi-traversal",
                  "nosqli-login", "xss-reflected", "crlf-inject",
                  "proto-pollution", "jndi-oob", "xxe-callback",
                  "host-header-poison"],
    "AUTH": ["jwt-weak-secret", "jwt-alg-confusion", "reset-enum",
             "host-header-poison", "mass-assignment"],
    "CACHE": ["cache-deception"],
    "RCE": ["deser-rce", "ssti-eval", "rce-marker"],
    "EXPOSURE": ["lfi-traversal", "open-redirect"],
    "TAKEOVER": [],
    "SURFACE": ["sqli-products", "xss-reflected", "open-redirect"],
    "AI": ["prompt-injection", "llm-output", "rag-poisoning"],
}


def load_leads(findings_path: Path) -> list[dict]:
    doc = json.loads(findings_path.read_text(encoding="utf-8"))
    leads = []
    for f in doc.get("findings", []):
        if not isinstance(f, dict):
            continue
        if f.get("verdict", 0) >= 1 and f.get("status") == "confirmed" \
                and f.get("category") not in ("AMAN", "MISC"):
            leads.append(f)
    return leads[:MAX_LEADS]


def _lead_param(lead: dict) -> str | None:
    p = (lead.get("extra") or {}).get("param") if "extra" in lead \
        else lead.get("param")
    return str(p) if p else None


def _lead_path(lead: dict) -> str | None:
    tu = lead.get("target_url") or ""
    m = re.match(r"https?://[^/]+(/[^?#]*)?", tu)
    path = m.group(1) if m else None
    return path if path and path != "/" else None


def deterministic_plan(leads: list[dict], params_override: dict) -> dict:
    """Mapping kategori lead -> playbook + params derivable. Tanpa
    request; param yang tidak derivable = blocked (butuh operator)."""
    steps: list[dict] = []
    seen: set[tuple] = set()
    for lead in leads:
        cats = [lead.get("category")] + \
               [c for c in CATEGORY_MAP if c in str(lead.get("title", ""))]
        for cat in cats:
            for pb in CATEGORY_MAP.get(cat, []):
                spec = PARAM_SPECS.get(pb)
                if spec is None:
                    continue
                params = dict(spec.get("defaults", {}))
                blocked = []
                for req in spec.get("required", []):
                    src = spec.get("auto", {}).get(req)
                    if src == "lead_path" and _lead_path(lead):
                        params[req] = _lead_path(lead)
                    elif src == "lead_param" and _lead_param(lead):
                        params[req] = _lead_param(lead)
                    elif f"{pb}.{req}" in params_override:
                        params[req] = params_override[f"{pb}.{req}"]
                    else:
                        blocked.append(req)
                for k, v in params_override.items():
                    if k.startswith(pb + ".") and \
                            k.split(".", 1)[1] not in params:
                        params[k.split(".", 1)[1]] = v
                key = (pb, tuple(sorted(params.items())))
                if key in seen:
                    continue
                seen.add(key)
                steps.append({
                    "playbook": pb, "tier": ep.PLAYBOOKS[pb].tier,
                    "category": cat,
                    "source_lead": lead.get("id", "")[:16],
                    "params": params,
                    "blocked": blocked,
                    "rationale": f"lead '{lead.get('title', '')[:70]}' "
                                 f"(kategori {cat})"})
    return {"mode": "proof", "steps": steps}


LLM_SYSTEM = (
    "Kamu merencanakan pengujian keamanan BEROTORISASI (lab/staging/"
    "program dengan izin tertulis). Pilih playbook HANYA dari daftar "
    "yang diberikan dan isi params dari bukti yang diberikan. Jangan "
    "mengarang playbook atau parameter baru. Balas JSON tunggal: "
    '{"steps": [{"playbook": "<nama>", "params": {...}, "rationale": '
    '"<singkat>"}]}. Tanpa teks lain.')


def llm_plan(llm_url: str, model: str, leads: list[dict],
             params_override: dict, timeout: float = 120.0) -> tuple[
        dict, list[str]]:
    """Slot LLM: minta susunan langkah, VALIDASI keras, return
    (plan, rejections). Tidak ada request ke target di sini."""
    menu = {name: {"tier": pb.tier, "desc": pb.desc,
                   "params": PARAM_SPECS.get(name, {})}
            for name, pb in ep.PLAYBOOKS.items()}
    user = json.dumps({"leads": [
        {"id": l.get("id", "")[:16], "category": l.get("category"),
         "title": l.get("title", "")[:120],
         "target_url": l.get("target_url", ""),
         "param": _lead_param(l)} for l in leads],
        "playbook_menu": menu,
        "operator_params": sorted(params_override)}, ensure_ascii=False)
    body = json.dumps({"model": model, "temperature": 0,
                       "messages": [{"role": "system",
                                     "content": LLM_SYSTEM},
                                    {"role": "user",
                                     "content": user}]}).encode()
    req = urllib.request.Request(llm_url, data=body, method="POST",
                                 headers={"Content-Type":
                                          "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = json.loads(r.read(4_000_000).decode("utf-8", "replace"))
    content = (raw.get("choices") or [{}])[0].get("message", {}) \
        .get("content", "")
    m = re.search(r"\{.*\}", content, re.S)
    if not m:
        return {"mode": "proof", "steps": []}, [
            "LLM: tidak ada JSON di respons"]
    try:
        doc = json.loads(m.group(0))
    except Exception as exc:
        return {"mode": "proof", "steps": []},
        [f"LLM: JSON cacat ({exc})"]
    steps, rejections = [], list(doc.get("rejections", []))
    for st in doc.get("steps", []):
        pb = str(st.get("playbook", ""))
        if pb not in ep.PLAYBOOKS:
            rejections.append(f"playbook tidak di registry: {pb!r}")
            continue
        spec = PARAM_SPECS.get(pb, {"required": [], "auto": {},
                                    "defaults": {}})
        allowed = set(spec.get("required", [])) \
            | set(spec.get("auto", {})) | set(spec.get("defaults", {}))
        params = dict(spec.get("defaults", {}))
        bad = [k for k in (st.get("params") or {})
               if k not in allowed]
        if bad:
            rejections.append(f"{pb}: param tidak dikenal {sorted(bad)}")
            continue
        unknown = [k for k in spec.get("required", [])
                   if k not in (st.get("params") or {})
                   and k not in params
                   and f"{pb}.{k}" not in params_override]
        if unknown:
            rejections.append(f"{pb}: param kurang {unknown} "
                              "(butuh operator)")
            continue
        params.update(st.get("params") or {})
        for k, v in params_override.items():
            if k.startswith(pb + "."):
                params[k.split(".", 1)[1]] = v
        steps.append({"playbook": pb,
                      "tier": ep.PLAYBOOKS[pb].tier,
                      "params": params,
                      "blocked": [],
                      "rationale": str(st.get("rationale", ""))[:200] +
                      " [llm]"})
    return {"mode": "proof", "steps": steps, "llm": True}, rejections


def emit_engine_config(plan: dict, target: dict, out: Path) -> None:
    """Config engine dari rencana — exploit_allowed SELALU false
    (operator yang melipatnya secara sadar, fail-closed)."""
    params = {s["playbook"]: s["params"] for s in plan["steps"]
              if not s.get("blocked")}
    names = sorted(params)
    cfg = {"targets": [{**{k: v for k, v in target.items()
                           if k in ("id", "base_url", "credentials",
                                    "params")},
                        "id": target.get("id", "planned"),
                        "base_url": target.get("base_url", ""),
                        "exploit_allowed": False, "mode": "proof",
                        "params": params}],
           "playbooks": names,
           "note": "di-emit attack_planner (fase 2) — exploit_allowed "
                   "SELALU false; baca docs/EXPLOIT-TIER.md lalu lipat "
                   "secara sadar bila target terotorisasi"}
    out.write_text(json.dumps(cfg, ensure_ascii=False, indent=1) + "\n",
                   encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out", required=True, help="path attack-plan.json")
    ap.add_argument("--base-url", default="",
                    help="target untuk config emit (wajib --emit-config)")
    ap.add_argument("--target-id", default="planned")
    ap.add_argument("--credentials", default="",
                    help="JSON dict kredensial untuk config emit")
    ap.add_argument("--emit-config", default="",
                    help="juga tulis config engine (exploit_allowed=false)")
    ap.add_argument("--llm-url", default="",
                    help="endpoint OpenAI-compatible (mis. Ollama "
                         "/v1/chat/completions); kosong = deterministic")
    ap.add_argument("--llm-model", default="")
    ap.add_argument("--param", action="append", default=[],
                    metavar="PLAYBOOK.KEY=VALUE",
                    help="isi parameter yang butuh operator")
    args = ap.parse_args(argv)

    params_override: dict = {}
    for kv in args.param:
        k, _, v = kv.partition("=")
        params_override[k.strip()] = v

    fp = Path(args.findings)
    if not fp.exists():
        print(f"findings tidak ada: {fp} (fail-closed)", file=sys.stderr)
        return 2
    leads = load_leads(fp)
    if not leads:
        print("[planner] tidak ada lead substantif — rencana kosong "
              "(tanpa bukti, tanpa rencana)", file=sys.stderr)

    plan, rejections = deterministic_plan(leads, params_override), []
    if args.llm_url:
        if not args.llm_model:
            print("--llm-url butuh --llm-model", file=sys.stderr)
            return 2
        plan, rejections = llm_plan(args.llm_url, args.llm_model, leads,
                                    params_override)

    blocked = [s for s in plan["steps"] if s.get("blocked")]
    ready = [s for s in plan["steps"] if not s.get("blocked")]
    plan.update({"leads": len(leads), "steps_ready": len(ready),
                 "steps_blocked": len(blocked),
                 "rejections": rejections,
                 "disclaimer": "rencana saja — eksekusi lewat exploit "
                               "engine gate (exploit_allowed)"})
    Path(args.out).write_text(json.dumps(plan, ensure_ascii=False,
                                         indent=1) + "\n", encoding="utf-8")
    print(f"[planner] {len(leads)} lead -> {len(ready)} langkah siap, "
          f"{len(blocked)} butuh operator, {len(rejections)} ditolak "
          f"-> {args.out}")
    if args.emit_config:
        if not args.base_url:
            print("--emit-config butuh --base-url", file=sys.stderr)
            return 2
        creds = json.loads(args.credentials) if args.credentials else {}
        emit_engine_config(plan, {"id": args.target_id,
                                  "base_url": args.base_url,
                                  "credentials": creds},
                           Path(args.emit_config))
        print(f"[planner] config engine (exploit_allowed=false) -> "
              f"{args.emit_config}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
