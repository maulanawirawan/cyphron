"""tierpack_bounty - HARVEST Bug Bounty (2026-09-06): yaklang/hack-skills (101
skill, 2.1k), matty69v/Bug-Bounty-Agents (43 agen), skraft9/vulnerability-research,
PatientZero (WSTG chaining), OwlShield (LLM firewall -> AI probe), Rise The Ranger
2 (AD/Forensics/IR). Hanya skill BARU yang belum ada di skills-tiers2/3."""

from __future__ import annotations

from pathlib import Path

from .tierpack import CVSS

TIERS = {
    "low": [
        ("param-miner-basic", "Param tersembunyi ditambang via diff respons (arjun-style)", "hit = param mengubah respons vs baseline", "live:param_miner"),
        ("csv-formula-injection", "Payload =cmd/@SUM di field CSV export", "hit = formula terpantul di output CSV", "road:csv_inj"),
        ("dangling-markup-injection", "<img src=//canary terpantul di respons", "hit = canary url dalam markup", "road:dangle"),
        ("hpp-parameter-pollution", "Param ganda mengubah logika server", "hit = respons beda vs param tunggal", "road:hpp"),
        ("sri-missing-cdn", "Script cross-origin tanpa integrity SRI", "definitif: atribut integrity", "road:sri"),
        ("cookie-attrs-audit", "SameSite/Domain/Expires cookie di-audit", "definitif: atribut Set-Cookie", "road:cookie_audit"),
        ("meta-refresh-redirect", "Redirect tersembunyi via meta refresh", "hit = navigasi ke canary", "road:meta_redir"),
        ("response-timing-oracle", "Oracle timing untuk enum username (CWE-208)", "hit = delta latency konsisten", "road:timing_oracle"),
    ],
    "medium": [
        ("nosql-operator-injection", "Operator Mongo $ne/$gt di body JSON", "hit = auth lolos / error Mongo", "road:nosql"),
        ("gql-field-suggestion", "DidYouMean GraphQL bocorkan skema", "hit = suggestion nama field asli", "road:gql_suggest"),
        ("password-reset-enumeration", "Respons reset password beda per username", "hit = enum via diff respons", "road:reset_enum"),
        ("signup-mass-assignment", "role/isAdmin di body registrasi diterima", "hit = akun baru ber-role naik", "road:massassign"),
        ("prompt-injection-ai-endpoint", "Payload jailbreak ke endpoint AI/LLM (OwlShield angles)", "hit = output melewati policy", "live:llm_probe"),
        ("waf-fingerprint-evasion-matrix", "Peta WAF + matriks bypass aman (Cloudflare/AWS)", "hit = payload lolos terukur", "road:waf_matrix"),
        ("open-redirect-meta-chain", "Rantai meta/JS redirect ke canary", "hit = navigasi berakhir di canary", "road:redir_chain"),
        ("api-mass-docs-drift", "Bandung spec OpenAPI vs endpoint live", "hit = endpoint tidak terdokumentasi", "road:drift_bounty"),
        ("subdomain-permute-dns", "Permutasi subdomain + resolve batch", "hit = hostname baru ter-resolve", "road:sub_permute"),
        ("cors-reflect-strict", "Origin terpantul di ACAO tanpa wildcard", "hit = ACAO = origin canary + ACAC true", "road:cors_strict"),
    ],
    "high": [
        ("authz-bypass-401-403", "Matriks bypass 401/403: path tricks, X-Original-URL, verb", "hit = 200 konten nyata via bypass", "live:authz_bypass"),
        ("subdomain-takeover-fingerprint", "CNAME dangling + fingerprint provider (S3/GH/Azure)", "hit = fingerprint brand definitif", "live:takeover"),
        ("race-condition-bounded", "Race bounded: N request paralel, hitung sukses ganda", "hit = >1 sukses untuk aksi sekali", "road:race"),
        ("http2-content-based-smuggle", "CRLF di HTTP/2 header name/value (CL.0)", "hit = respons desync definitif", "road:h2_crlf"),
        ("js-analysis-endpoint-harvest", "Harvest endpoint/API dari bundle JS (LinkFinder-style)", "hit = endpoint baru dari JS", "road:js_harvest"),
        ("cache-key-normalization-bounty", "Normalisasi cache key (; / ../ %09) -> poison", "hit = cache menyajikan payload", "road:cache_norm"),
        ("csrf-token-not-bound", "CSRF token tidak terikat sesi", "hit = token A dipakai sesi B sukses", "road:csrf_bind"),
        ("jwt-null-signature", "Signature kosong/none di token", "hit = token tanpa sig diterima", "road:jwt_null"),
    ],
    "critical": [
        ("takeover-payload-provider", "Bukti takeover: body provider + resource id kita", "hit = konten kontrol kita di subdomain", "road:takeover2"),
        ("sso-saml-assertion-tamper", "Tamper assertion SAML (unsigned)", "hit = login sebagai korban", "road:saml"),
        ("webhook-secret-bypass", "Webhook tanpa verifikasi signature HMAC", "hit = payload palsu diproses", "road:wh_sig"),
        ("graphql-dataloader-leak", "Batching resolver bocorkan objek lintas owner", "hit = objek owner lain di respons", "road:gql_dataloader"),
        ("llm-agent-tool-abuse", "Prompt injection memicu tool agen AI (browser/db)", "hit = tool dipanggil dgn canary", "road:llm_tool"),
        ("payment-amount-tamper-race", "Tamper amount + race pada checkout", "hit = order sukses < nilai", "road:pay_race"),
        ("cloud-bucket-takeover-signal", "Bucket/S3 endpoint dangling milik target", "hit = NoSuchBucket di domain target", "road:bucket_sig"),
    ],
}


def build_bounty(kimchi_dir: Path) -> dict:
    from .tierpack import _render
    out_root = kimchi_dir / "skills-bounty"
    stats, live, total = {}, 0, 0
    index = ["# Cyphron Bug Bounty Pack - HARVEST 6 sumber (2026-09-06)", "",
             "Sumber: yaklang/hack-skills (101 skill), matty69v/Bug-Bounty-Agents",
             "(43 agen), skraft9/vulnerability-research, patientzerosecurity.com,",
             "owlshield.ai, Rise The Ranger 2 (Satsiber TNI). Skill BARU di luar",
             "skills-tiers2/3. FP-guard + truth-guarantee per skill.", ""]
    for tier, rows in TIERS.items():
        tdir = out_root / tier
        tdir.mkdir(parents=True, exist_ok=True)
        for i, (name, technique, guard, engine) in enumerate(rows, start=1):
            (tdir / f"{tier}-{i:02d}-{name}.md").write_text(
                _render(tier, i, name, technique, guard, engine), encoding="utf-8")
            total += 1
            if engine.startswith("live"):
                live += 1
        stats[tier] = len(rows)
        index.append(f"## {tier.upper()} - {len(rows)} skills (CVSS {CVSS[tier]})")
        for i, (name, _t, _g, engine) in enumerate(rows, start=1):
            tag = "LIVE" if engine.startswith("live") else "ROADMAP"
            index.append(f"- {tier}-{i:02d} [{tag}] {name} -> {engine.split(':', 1)[1]}")
        index.append("")
    index.append("Coverage: %d LIVE / %d ROADMAP" % (live, total - live))
    (out_root / "INDEX.md").write_text(chr(10).join(index), encoding="utf-8")
    return {"root": str(out_root), "stats": stats, "total": total, "live": live}
