"""[SAFETY: read-only] llm-endpoint-surface — permukaan AI/LLM dari bukti HTML/JS

Batch 10 / F44 (docs/TOPIC-RESEARCH-AI-2026-10.md §3): pemetaan
permukaan AI/LLM milik target DARI BUKTI tersimpan — NOL request.
Marker EKSPLISIT saja (path API generasi, nama model, framework
berkait) = L1 inventaris; tanpa marker = AMAN. Anti-FP: token ketat —
kata generik ("chat", "ai", "bot") TIDAK PERNAH dihitung; tebakan
tidak ada.

Bukti dari raw evidence (pola sama tech-fingerprint): --from-raw.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

# Path API generasi/LLM yang tidak ambigu (versi eksplisit / nama vendor)
RE_API_PATH = re.compile(
    r"(?:/v1/chat/completions|/v1/completions|/v1/messages|"
    r"/v1beta/models|/api/generate|/api/embeddings|/api/embed|"
    r"/api/tags)", re.I)
# Nama model: token vendor + penanda versi/polisian, bukan kata umum
RE_MODEL = re.compile(
    r"\b(?:gpt-[0-9o]|claude-[a-z0-9]|llama-?[0-9]|gemini-[0-9.]|"
    r"mistral-[0-9a-z]|mixtral|qwen[0-9.-]|deepseek-?|phi-[0-9]|"
    r"granite-[0-9])", re.I)
# Framework/runtime AI yang eksplisit disebut di bukti
RE_FRAMEWORK = re.compile(
    r"\b(?:openai|anthropic|ollama|vllm|llamacpp|llama\.cpp|langchain|"
    r"llamaindex|text-generation-webui|open-webui|lobechat|nextchat)\b",
    re.I)


def audit(url: str, evidence: str) -> tuple[list[dict], dict]:
    """Murni: bukti HTML/JS -> (rows, meta) kontrak. L1 inventaris per
    kelas marker (maks 1 baris per kelas, marker di extra)."""
    blob = evidence or ""
    api_paths = sorted(set(m.group(0).lower()
                           for m in RE_API_PATH.finditer(blob)))[:12]
    models = sorted(set(m.group(0).lower()
                        for m in RE_MODEL.finditer(blob)))[:12]
    frameworks = sorted(set(m.group(0).lower()
                            for m in RE_FRAMEWORK.finditer(blob)))[:12]
    detected = []
    if api_paths:
        detected.append(("api-generasi LLM", api_paths))
    if models:
        detected.append(("nama model", models))
    if frameworks:
        detected.append(("framework/runtime AI", frameworks))
    rows: list[dict] = []
    if detected:
        detail = "; ".join(f"{label}: {', '.join(mark)}"
                           for label, mark in detected)
        rows.append(make_finding(
            tool="llm-endpoint-surface",
            title=f"Permukaan AI/LLM terdeteksi di bukti {url}",
            severity="info",
            description=f"Marker AI/LLM EKSPLISIT di bukti tersimpan "
                        f"(inventaris, NOL request): {detail}. Permukaan "
                        "ini layak masuk rencana uji postur (mis. "
                        "playbook prompt-injection pada endpoint "
                        "generasi milik sendiri).",
            recommendation="Uji postur endpoint generasi milik sendiri "
                           "(prompt-injection) dalam scope terotorisasi.",
            cwe=None, target_url=url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class": "read-only",
                   "api_paths": api_paths, "models": models,
                   "frameworks": frameworks}))
    else:
        rows.append(make_finding(
            tool="llm-endpoint-surface",
            title=f"Tidak ada marker AI/LLM eksplisit di bukti {url}",
            severity="info",
            description="Tidak ada path API generasi, nama model, atau "
                        "framework AI eksplisit di bukti — permukaan AI "
                        "tidak teramati (AMAN/inventaris, NOL request).",
            target_url=url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "read-only",
                   "api_paths": [], "models": [], "frameworks": []}))
    return rows, {"url": url, "requests": 0,
                  "api_paths": api_paths, "models": models,
                  "frameworks": frameworks}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] llm-endpoint-surface dari bukti")
    ap.add_argument("--url", default="@(unknown)")
    ap.add_argument("--from-raw", required=True,
                    help="file bukti HTML/JS tersimpan (NOL request)")
    ap.add_argument("--out", default="llm_endpoint_surface.json")
    args = ap.parse_args()
    p = Path(args.from_raw)
    if not p.exists():
        print(f"bukti tidak ada: {p} (fail-closed, NOL request)",
              file=sys.stderr)
        return 2
    evidence = p.read_text(encoding="utf-8", errors="replace")
    rows, meta = audit(args.url, evidence)
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    n = 1 if meta["api_paths"] or meta["models"] or meta["frameworks"] else 0
    print(f"llm-endpoint-surface: {n} permukaan AI (0 request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
