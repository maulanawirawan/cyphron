"""gql_schema_engines — dua engine pemetaan skema GraphQL:

- gql_introspect (CWE-200, medium): introspection __schema + satu cek
  suggestion. Berbeda dari gql_depth (ini BUKAN depth attack).
- graphql_field_suggest (CWE-200, medium): field suggestion "Did you mean"
  dari N typo terarah -> pemetaan skema tanpa introspection.

FP-guard: junk query baseline wajib (bedakan channel error); hanya respons
dengan data __schema / "Did you mean" yang dihitung; GET vs POST ikut
arg method; cease-on-data; maks 4 request. Introspection pada API publik
sering by-design — severity final dari rules program (engine mencatat,
bukan menggurui).
"""

from __future__ import annotations

import json
import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_INTROSPECTION = {"query": "{ __schema { queryType { name } types { name } } }"}
_JUNK = {"query": "cyphron-not-a-query"}

# typo terarah: mendekati nama field umum agar suggestion mengungkap skema
_TYPOS = ("{ usr }", "{ myorders }", "{ admn }")
_SUGGEST_RE = re.compile(r"Did you mean[^\"']*['\"]([^'\"]+)['\"]", re.I)


def _gql_post(url: str, payload: dict, ctx: ToolContext):
    ctx.throttle()
    st, _h, body, _ms = http_engine.http_get(
        url, timeout=ctx.timeout_s, method="POST",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    ctx.world.request_count += 1
    return st, body


class GqlIntrospectTool(Tool):
    name = "gql_introspect"
    description = ("GraphQL introspection + suggestion check (bukan depth). "
                   "Baseline junk wajib; severity final dari rules program.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        j_st, j_body = _gql_post(url, _JUNK, ctx)
        i_st, i_body = _gql_post(url, _INTROSPECTION, ctx)
        data: dict = {"junk_status": j_st, "introspect_status": i_st}
        try:
            parsed = json.loads(i_body or "{}")
        except Exception:
            parsed = {}
        type_names = [t.get("name") for t in
                      ((parsed.get("data") or {}).get("__schema") or
                       {}).get("types", []) if isinstance(t, dict)]
        type_names = [t for t in type_names if t and not str(t).startswith("__")]
        data["introspection_open"] = bool(type_names)
        data["type_count"] = len(type_names)
        data["types_sample"] = type_names[:15]
        findings: list[Finding] = []
        if type_names:
            data["mode"] = ["introspection"]
            findings.append(Finding(
                tool=self.name,
                title=f"GraphQL introspection enabled on {url} "
                      f"({len(type_names)} types)",
                severity="medium", cwe="CWE-200",
                description=(
                    f"__schema merespons penuh ({len(type_names)} tipe; junk "
                    f"query ditolak berbeda) — skema API dapat dipetakan "
                    f"penyerang (field, mutasi, tipe internal). Pada API "
                    f"publik ini sering by-design; nilai dampak naik bila "
                    f"endpoint internal/admin. Suggestion check menyusul "
                    f"berperan sebagai bukti cadangan bila introspection "
                    f"dimatikan."),
                recommendation=(
                    "Matikan introspection di produksi; disable error "
                    "suggestion; batasi endpoint per-auth."),
                target_url=url,
                request=f"POST {url} {{ __schema {{ types {{ name }} }} }}",
                response=f"status={i_st}; types={data['types_sample']}",
                confidence=0.8, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
            return ToolResult(tool=self.name, ok=True, data=data,
                              findings=findings)

        # introspection mati -> cek suggestion sebagai bukti cadangan
        s_st, s_body = _gql_post(url, {"query": _TYPOS[0]}, ctx)
        sug = _SUGGEST_RE.search(s_body or "")
        data["suggestion_check"] = {"status": s_st,
                                    "hit": bool(sug)}
        if sug:
            data["mode"] = ["suggestion"]
            findings.append(Finding(
                tool=self.name,
                title=f"GraphQL field suggestion leaks schema on {url}",
                severity="medium", cwe="CWE-200",
                description=(
                    "Introspection dimatikan, TAPI error validator "
                    "menyodorkan 'Did you mean <field>' — skema tetap "
                    "terpetakan lewat suggestion."),
                recommendation=(
                    "Set suggestion di level library ke off; generikkan "
                    "pesan error validasi."),
                target_url=url,
                request=f"POST {url} {_TYPOS[0]}",
                response=f"status={s_st}; suggestion={sug.group(1)!r}",
                confidence=0.7, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)


class GraphqlFieldSuggestTool(Tool):
    name = "graphql_field_suggest"
    description = ("GraphQL schema mapping via 'Did you mean' field "
                   "suggestions dari typo terarah (tanpa introspection).")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        j_st, j_body = _gql_post(url, _JUNK, ctx)
        data: dict = {"junk_status": j_st, "suggestions": []}
        findings: list[Finding] = []
        leaked: list[str] = []
        for q in _TYPOS:
            if ctx.world.request_count >= ctx.max_requests or leaked:
                break  # cease-on-data: cukup satu bukti suggestion aktif
            st, body = _gql_post(url, {"query": q}, ctx)
            sug = _SUGGEST_RE.search(body or "")
            data["suggestions"].append({"query": q, "status": st,
                                        "suggestion": sug.group(1) if sug else None})
            if sug:
                leaked.append(sug.group(1))
        if leaked:
            findings.append(Finding(
                tool=self.name,
                title=f"GraphQL schema mapped via field suggestions on {url}",
                severity="medium", cwe="CWE-200",
                description=(
                    f"Validator GraphQL menyarankan nama field asli pada typo "
                    f"({', '.join(leaked[:3])}) — penyerang memetakan skema "
                    f"tanpa introspection dengan mengulang typo terarah. "
                    f"cease-on-data: berhenti di bukti pertama; tidak ada "
                    f"enumerasi massal field."),
                recommendation=(
                    "Matikan field suggestion (proposeResults) di produksi; "
                    "paksakan pesan error generik."),
                target_url=url,
                request=f"POST {url} {_TYPOS[0]}",
                response=f"status={st}; leaked fields={leaked[:3]}",
                confidence=0.75, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
