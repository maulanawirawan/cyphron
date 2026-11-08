r"""[SAFETY: read-only] oauth_grant_audit — audit OFFLINE inventaris
OAuth grant/scope pihak ketiga (ekspor Microsoft Graph
oauth2PermissionGrants / daftar grant generik): klasifikasi risiko scope,
konsen admin-tenant, izin application (all-user), bandingkan dgn katalog
approved -> temuan over-permission. TANPA jaringan.

Mengisi antrean port SKILL-PORT-QUEUE #0860 (mukul975/
Anthropic-Cybersecurity-Skills 'performing-oauth-scope-minimization-
review'; atribusi konsep, lisensi sumber Apache-2.0). Skill sumber
menghimpun inventaris via Graph API LIVE; inti deterministik yang
diekstrak di sini = ANALISIS inventaris yang sudah diekspor:
klasifikasi risiko scope, agregasi skor per aplikasi, diff vs katalog
approved — from scratch (tabel klasifikasi konsep ditulis ulang, bukan
salinan kode).

Pembagian ranah (TIDAK diduplikasi):
  - validasi struktur token JWT -> jwt_token_audit
  - eskalasi role AWS/IAM -> iam_escalation_scan
  - enum grant LIVE via Graph API = sisi jaringan skill sumber (tidak
    diport — ekspor JSON dulu di lab, lalu audit di sini)
  - di sini: analisis inventaris grant offline.

Input -> mekanisme -> output:
  - Input : --grants JSON, dua bentuk dikenali per-entri:
            (a) ekspor Graph: {"value":[{clientId, scope:"A B",
                consentType:"Principal"|"AllPrincipals", ...}]}
            (b) generik: [{"app_name"| "app_id", "permission_type":
                "delegated"|"application", "scope": "A B",
                "consent": "user"|"admin"}]
            Opsional: --principals JSON Graph (id->displayName),
            --catalog JSON {app: {"approved_scopes":[...]}} atau
            [{"app":..., "approved_scopes":[...]}]. Baca-saja.
  - Mekanisme: tiap grant -> pecah scope (whitespace) -> klasifikasi
            risiko (tabel seed Graph + pola sufiks .ReadWrite.All/
            .Read.All/.FullControl.*; TAK DIKENAL = high + flag unknown,
            fail-closed) -> agregat per aplikasi (bobot 40/20/10/2 +
            15 per application-permission + 10 per konsen admin) ->
            temuan: konsen-admin-tenant dgn scope kritis, application
            permission kritis, aplikasi tak-terdaftar, scope melebihi
            katalog, downgrade ReadWrite->Read yang tersedia.
  - Output: JSON {schema, stats, apps, findings, notes}.

Cek:
  admin-consent-critical (high): konsen tenant-wide (AllPrincipals/
                         admin) + scope kritis.
  app-permission-critical (high): permission_type application + scope
                         kritis (akses seluruh user tanpa konteks).
  unapproved-app         (high): aplikasi tak ada di katalog (butuh
                         --catalog).
  excessive-scope        (high/medium): scope di luar approved_scopes
                         (severity = risiko tertinggi scope-nya).
  over-broad-scope       (medium): X.ReadWrite diberikan sementara
                         katalog hanya menyetujui X.Read — saran
                         downgrade.
  app-aggregate-critical (high): skor agregat >= 100 (CRITICAL).
  scope-unknown          (high): scope di luar tabel & pola — butuh
                         klasifikasi manual (fail-closed, bukan diam).

Fail-closed:
  - --grants/--catalog/--principals JSON rusak -> exit 2.
  - nol grant dikenali (bentuk tak dikenal semua) -> exit 2.
  - scope tak dikenal = temuan high + flag unknown (tidak pernah
    diasumsikan aman).
  - deteksi GRANT STALE (tak terpakai 90 hari) butuh log sign-in yang
    TIDAK ada di inventaris — dilaporkan sebagai keterbatasan di notes,
    bukan temuan palsu.

Anti-FP: pencocokan scope case-insensitive persis token; pola sufiks
hanya utk bentuk Graph standar; --fail-on default medium.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error input.

Pemakaian:
  python tools/oauth_grant_audit.py --grants grants.json --out audit.json
  python tools/oauth_grant_audit.py --grants grants.json \
      --principals sp.json --catalog approved.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "cyphron.oauth-grant-audit/1"
MAX_FILE_BYTES = 64 * 1024 * 1024

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_WEIGHT = {"critical": 40, "high": 20, "medium": 10, "low": 2}

CRITICAL_SCOPES = {
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
    "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
    "Sites.FullControl.All", "User.ReadWrite.All", "Group.ReadWrite.All",
    "MailboxSettings.ReadWrite", "full_access_as_app",
}
HIGH_SCOPES = {
    "Mail.Read", "Mail.Read.Shared", "Calendars.ReadWrite",
    "Contacts.ReadWrite", "Files.Read.All", "Sites.Read.All",
    "User.Read.All", "Group.Read.All", "Directory.Read.All",
    "AuditLog.Read.All", "SecurityEvents.ReadWrite.All",
    "TeamSettings.ReadWrite.All",
}
MEDIUM_SCOPES = {
    "Calendars.Read", "Contacts.Read", "Files.ReadWrite",
    "Sites.ReadWrite.All", "Tasks.ReadWrite", "Notes.ReadWrite.All",
    "Chat.ReadWrite", "ChannelMessage.Send", "Team.ReadBasic.All",
}
LOW_SCOPES = {
    "User.Read", "openid", "profile", "email", "offline_access",
    "Calendars.Read.Shared", "People.Read", "User.ReadBasic.All",
}

READWRITE_PATTERNS = (".ReadWrite.All", ".FullControl.All",
                      ".FullControl")
READ_ALL_PATTERN = ".Read.All"


def classify_scope(scope: str) -> "tuple[str, bool]":
    """(risk, unknown) — case-insensitive; pola sufiks Graph standar."""
    s = scope.strip()
    if not s:
        return "low", False
    low = s.lower()
    if s in CRITICAL_SCOPES or low == "*" or low == "all":
        return "critical", False
    if s in HIGH_SCOPES:
        return "high", False
    if s in MEDIUM_SCOPES:
        return "medium", False
    if s in LOW_SCOPES:
        return "low", False
    if low.endswith(tuple(p.lower() for p in READWRITE_PATTERNS)):
        return "critical", False
    if low.endswith(READ_ALL_PATTERN.lower()):
        return "high", False
    if low.endswith(".readwrite"):
        return "medium", False
    if low.endswith(".read"):
        return "medium", False
    return "high", True  # tak dikenal = fail-closed, bukan aman


def _norm_consent(consent: str) -> str:
    c = (consent or "").strip().lower()
    if c in ("allprincipals", "admin", "adminconsent"):
        return "admin"
    return "user"


def _norm_type(ptype: str) -> str:
    t = (ptype or "").strip().lower()
    if t in ("application", "approle", "role", "app"):
        return "application"
    return "delegated"


def _parse_grants(doc: "dict | list") -> "tuple[list[dict], int]":
    """Kembalikan (grants ternormalisasi, jumlah entri bentuk-asing)."""
    if isinstance(doc, dict):
        raw = doc.get("value", [])
        shape = "graph"
    elif isinstance(doc, list):
        raw = doc
        shape = "flat"
    else:
        return [], 1
    grants: "list[dict]" = []
    foreign = 0
    for ent in raw:
        if not isinstance(ent, dict):
            foreign += 1
            continue
        if shape == "graph":
            app = ent.get("clientId") or ""
            scopes = (ent.get("scope") or "")
            consent = _norm_consent(ent.get("consentType", ""))
            ptype = "delegated"
        else:
            app = ent.get("app_name") or ent.get("app") or \
                ent.get("app_id") or ent.get("clientId") or ""
            scopes = (ent.get("scope") or "")
            consent = _norm_consent(ent.get("consent", ""))
            ptype = _norm_type(ent.get("permission_type", ""))
        if not app or not str(scopes).strip():
            foreign += 1
            continue
        grants.append({"app": str(app), "ptype": ptype,
                       "scopes": str(scopes).split(),
                       "consent": consent})
    return grants, foreign


def _parse_catalog(doc: "object") -> "dict[str, set[str]]":
    cat: "dict[str, set[str]]" = {}
    if isinstance(doc, dict):
        if isinstance(doc.get("apps"), dict):
            doc = doc["apps"]
        for name, val in doc.items():
            if isinstance(val, dict):
                scopes = val.get("approved_scopes", [])
            else:
                scopes = val or []
            cat[str(name)] = {str(s) for s in scopes}
    elif isinstance(doc, list):
        for ent in doc:
            if isinstance(ent, dict):
                name = ent.get("app") or ent.get("name") or ""
                cat[str(name)] = {str(s) for s in
                                  ent.get("approved_scopes", [])}
    return cat


def audit(grants: "list[dict]", cat: "dict[str, set[str]]",
          principals: "dict[str, str] | None") -> \
        "tuple[list[dict], list[dict], dict]":
    findings: "list[dict]" = []
    apps: "dict[str, dict]" = {}
    stats: "dict[str, int]" = {"critical": 0, "high": 0, "medium": 0,
                               "low": 0, "unknown": 0, "grants": 0,
                               "foreign_entries": 0}

    def app_rec(name: str) -> dict:
        return apps.setdefault(name, {
            "app": name, "scopes": {}, "score": 0, "aggregate": "LOW",
            "application_permissions": 0, "admin_consents": 0})

    for g in grants:
        stats["grants"] += 1
        display = (principals or {}).get(g["app"], g["app"])
        rec = app_rec(display)
        for scope in g["scopes"]:
            risk, unknown = classify_scope(scope)
            stats[risk] += 1
            if unknown:
                stats["unknown"] += 1
            cur = rec["scopes"].get(scope)
            if cur is None or SEV_ORDER[risk] > SEV_ORDER[cur["risk"]]:
                rec["scopes"][scope] = {"risk": risk,
                                        "unknown": unknown,
                                        "ptype": g["ptype"],
                                        "consent": g["consent"]}
            if g["ptype"] == "application":
                rec["application_permissions"] += 1
            if g["consent"] == "admin":
                rec["admin_consents"] += 1
            # temuan per scope
            if g["consent"] == "admin" and risk == "critical":
                findings.append({
                    "check": "admin-consent-critical", "severity": "high",
                    "app": display, "scope": scope,
                    "message": f"scope KRITIS '{scope}' di-approve "
                               "tenant-wide (AllPrincipals) — seluruh "
                               "user terdampak; verifikasi kebutuhan & "
                               "publisher.",
                })
            if g["ptype"] == "application" and risk == "critical":
                findings.append({
                    "check": "app-permission-critical", "severity": "high",
                    "app": display, "scope": scope,
                    "message": f"APPLICATION permission kritis '{scope}' "
                               "— akses data SELURUH user tanpa konteks "
                               "user; review tiap kuartal.",
                })
            if unknown:
                findings.append({
                    "check": "scope-unknown", "severity": "high",
                    "app": display, "scope": scope,
                    "message": f"scope '{scope}' tidak ada di tabel & "
                               "pola — butuh klasifikasi manual "
                               "(fail-closed, tidak diasumsikan aman).",
                })
        # diff katalog
        if cat:
            approved = cat.get(display) or cat.get(g["app"])
            if approved is None:
                findings.append({
                    "check": "unapproved-app", "severity": "high",
                    "app": display,
                    "message": f"aplikasi '{display}' tidak ada di "
                               "katalog approved — review & revoke atau "
                               "daftarkan resmi.",
                })
            else:
                actual = set(g["scopes"])
                excess = actual - approved
                if excess:
                    worst = max(
                        (classify_scope(s)[0] for s in excess),
                        key=lambda r: SEV_ORDER[r])
                    findings.append({
                        "check": "excessive-scope",
                        "severity": "high"
                        if SEV_ORDER[worst] >= SEV_ORDER["high"]
                        else "medium",
                        "app": display,
                        "message": f"{len(excess)} scope di luar katalog "
                                   f"approved: {sorted(excess)[:8]} — "
                                   "hapus atau perbarui katalog.",
                    })
                for s in actual & approved:
                    low_s = s.lower()
                    if low_s.endswith(".readwrite"):
                        twin = s[:-len(".ReadWrite")] + ".Read"
                        if twin in approved:
                            findings.append({
                                "check": "over-broad-scope",
                                "severity": "medium", "app": display,
                                "message": f"'{s}' diberikan padahal "
                                           f"katalog menyetujui '{twin}' "
                                           "— downgrade minimasi scope.",
                            })

    # agregasi skor per aplikasi
    for rec in apps.values():
        score = 0
        for info in rec["scopes"].values():
            score += RISK_WEIGHT.get(info["risk"], 10)
        score += rec["application_permissions"] * 15
        score += rec["admin_consents"] * 10
        rec["score"] = score
        rec["aggregate"] = ("CRITICAL" if score >= 100
                            else "HIGH" if score >= 60
                            else "MEDIUM" if score >= 30 else "LOW")
        if rec["aggregate"] == "CRITICAL":
            findings.append({
                "check": "app-aggregate-critical", "severity": "high",
                "app": rec["app"],
                "message": f"skor agregat {score} (CRITICAL) — kombinasi "
                           "scope/izin paling berbahaya; prioritaskan "
                           "review aplikasi ini.",
            })
    findings_out = sorted(
        findings,
        key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                       f["check"], f.get("app", "")))
    apps_out = sorted(apps.values(), key=lambda r: -r["score"])
    for rec in apps_out:
        rec["scopes"] = [
            {"scope": s, **info}
            for s, info in sorted(rec["scopes"].items(),
                                  key=lambda kv:
                                  (-SEV_ORDER[kv[1]["risk"]], kv[0]))]
    return findings_out, apps_out, stats


def _load_json(path: str, label: str) -> "object":
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"file {label} tidak ada: {p}")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file {label} terlalu besar")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"JSON {label} rusak: {exc}") from exc


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit inventaris OAuth grant/scope offline, nol "
                    "jaringan.")
    ap.add_argument("--grants", required=True,
                    help="JSON ekspor Graph oauth2PermissionGrants ATAU "
                         "array grant generik")
    ap.add_argument("--principals", default=None,
                    help="JSON Graph servicePrincipals (id->nama, "
                         "opsional)")
    ap.add_argument("--catalog", default=None,
                    help="JSON katalog aplikasi disetujui (opsional)")
    ap.add_argument("--fail-on", default="medium",
                    choices=["info", "low", "medium", "high", "critical"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    try:
        grants_doc = _load_json(args.grants, "grants")
        principals: "dict[str, str] | None" = None
        if args.principals:
            sp = _load_json(args.principals, "principals")
            if isinstance(sp, dict):
                principals = {
                    str(s.get("id", "")): str(s.get("displayName", ""))
                    for s in sp.get("value", []) if isinstance(s, dict)
                    and s.get("id")}
        cat: "dict[str, set[str]]" = {}
        if args.catalog:
            cat = _parse_catalog(_load_json(args.catalog, "catalog"))
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    grants, foreign = _parse_grants(grants_doc)
    if not grants:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "nol grant dikenali (bentuk tidak cocok: Graph "
                     "{\"value\": [...]} atau array generik) — "
                     "fail-closed",
        }), file=sys.stderr)
        return 2

    findings, apps_out, stats = audit(grants, cat, principals)
    stats["foreign_entries"] = foreign
    stats["apps"] = len(apps_out)

    threshold = SEV_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEV_ORDER.get(f["severity"], 0) >= threshold]

    notes = [
        "analisis inventaris yang SUDAH diekspor — enum LIVE via Graph "
        "API tidak diport (sisi jaringan skill sumber); ekspor dulu di "
        "lab, audit di sini.",
        "deteksi GRANT STALE (tanpa aktivitas API 90 hari) butuh log "
        "sign-in servicePrincipal yang tidak ada di inventaris ini — "
        "keterbatasan, bukan kebersihan.",
        "scope tak dikenal dilaporkan scope-unknown (high) — tidak "
        "pernah diasumsikan aman; perluas tabel bila ada scope vendor "
        "baru.",
        "revoking integrasi bisnis kritis tanpa koordinasi = gangguan "
        "layanan — rencana remediasi butuh owner (cf. METHODS).",
    ]
    if stats.get("unknown"):
        notes.append(f"{stats['unknown']} scope tak dikenal perlu "
                     "klasifikasi manual sebelum verdict final.")

    report = {
        "schema": SCHEMA,
        "stats": stats,
        "apps": apps_out,
        "findings": findings,
        "notes": notes,
    }
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
