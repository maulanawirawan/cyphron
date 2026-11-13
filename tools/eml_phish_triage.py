"""[SAFETY: read-only] eml_phish_triage — triase OFFLINE header email untuk
investigasi phishing (rantai Received, hasil SPF/DKIM/DMARC, indikasi
spoofing, lampiran berbahaya).

Mekanisme (semua temuan = LEAD berbasis bukti, bukan klaim final):
  - replyto-mismatch   : Reply-To != From (indikasi klasik BEC)
  - returnpath-mismatch: domain Return-Path != domain From
  - auth-verdict       : dari Authentication-Results / Received-SPF
                         (fail/softfail/neutral/none — dmarc fail atau
                         dkim fail = high; softfail/neutral/none =
                         medium); TANPA header hasil autentikasi =
                         meta.auth_missing (jangan disimpulkan aman)
  - lookalike-domain   : butuh --legit (dapat berulang); homoglyph
                         (peta confusable + digit-swap, domain tampak
                         sama setelah normalisasi) = critical; edit-
                         distance ratio >= 0.8 = high
  - url-display-mismatch: teks tautan HTML memuat URL yang berbeda
                         dari href aktual
  - dangerous-attachment: ekstensi eksekusi/script/makro, ekstensi
                         ganda (mis. .pdf.exe = critical), hash
                         SHA-256 tiap lampiran disertakan

Header dengan defect tetap diproses (defect dicatat di meta.defects,
tidak crash). Fail-closed: file kosong / tanpa header RFC5322 ->
exit 2. URL & domain ditampilkan ter-defang (evil[.]com) di field
tampilan; nilai mentah hanya di evidence mesin.

Pemakaian:
  python tools/eml_phish_triage.py --eml phish.eml --out triase.json
  python tools/eml_phish_triage.py --eml m.eml --legit example-corp.com
Exit: 0 sukses (temuan tetap exit 0); 2 input error.
"""
from __future__ import annotations

import argparse
import email
import email.policy
import email.utils
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.eml-phish-triage/1"

_RE_URL = re.compile(r"https?://[^\s<>\"']+")
_RE_HREF = re.compile(
    r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
    re.DOTALL | re.IGNORECASE)
_RE_TAG = re.compile(r"<[^>]+>")
_RE_AUTH = {
    "spf": re.compile(r"(?i)\bspf[=:\s]+(pass|fail|softfail|neutral|"
                      "none|temperror|permerror)"),
    "dkim": re.compile(r"(?i)\bdkim[=:\s]+(pass|fail|softfail|neutral|"
                       "none|temperror|permerror)"),
    "dmarc": re.compile(r"(?i)\bdmarc[=:\s]+(pass|fail|softfail|neutral|"
                        "none|temperror|permerror)"),
}
_RE_DMARC_P = re.compile(r"(?i)\bp[=:\s]+(none|quarantine|reject)")
_RE_RECEIVED = re.compile(
    r"(?i)from\s+([^\s(]+)\s*(?:\(([^)]*)\))?(?:.*?\bby\s+([^\s;]+))?")

_RE_RECEIVED_SPF = re.compile(
    r"(?i)\breceived-spf\s*[=:]\s*(pass|fail|softfail|neutral|none|"
    "temperror|permerror)")

# confusable single-char map (subset umum homoglyph Cyrillic/Greek +
# digit-swap yang lazim di kampanye phishing)
_CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ѕ": "s", "ԁ": "d", "κ": "k", "ν": "v",
    "0": "o", "1": "l", "3": "e", "5": "s", "8": "b", "4": "a",
}

_EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".cpl", ".js", ".jse",
             ".vbs", ".vbe", ".wsf", ".hta", ".jar", ".bat", ".cmd",
             ".ps1", ".lnk", ".iso", ".img"}
_MACRO_EXT = {".docm", ".xlsm", ".xlam", ".dotm", ".pptm", ".xlm"}
_ARCHIVE_EXT = {".zip", ".rar", ".7z", ".cab"}

_UNPARSED_SAMPLE_MAX = 20


def _defang(value: str) -> str:
    """Defang tampilan: evil[.]com / hxxp agar tak bisa diklik."""
    out = value.replace(".", "[.]")
    return out.replace("://", "[://]")


def _domain_of(addr: str | None) -> str:
    if not addr:
        return ""
    return addr.rsplit("@", 1)[-1].strip().lower().rstrip(".")


def _normalize_domain(dom: str) -> str:
    return "".join(_CONFUSABLE.get(c, c) for c in dom.lower())


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def parse_auth(texts: list[str]) -> dict:
    """Kumpulkan verdict SPF/DKIM/DMARC dari header Authentication-
    Results (bisa lebih dari satu; ambil yang TERBURUK) + Received-SPF."""
    verdicts: dict[str, str] = {}
    sources: list[str] = []
    rank = {"fail": 5, "temperror": 4, "permerror": 3, "softfail": 2,
            "neutral": 2, "none": 1, "pass": 0}
    for text in texts:
        sources.append(text.strip()[:200])
        for method, rx in _RE_AUTH.items():
            m = rx.search(text)
            if not m:
                continue
            verdict = m.group(1).lower()
            old = verdicts.get(method)
            if old is None or rank.get(verdict, 0) > rank.get(old, 0):
                verdicts[method] = verdict
    return verdicts, sources


def _worst(methods: dict) -> tuple[str, str] | None:
    """(metode, verdict) terburuk menurut rank."""
    rank = {"fail": 5, "temperror": 4, "permerror": 3, "softfail": 2,
            "neutral": 2, "none": 1, "pass": 0}
    best = None
    for method, verdict in methods.items():
        if best is None or rank.get(verdict, 0) > rank.get(best[1], 0):
            best = (method, verdict)
    return best


def _received_chain(msg: email.message.Message) -> list[dict]:
    hops: list[dict] = []
    received = msg.get_all("Received") or []
    for raw in reversed(received):  # bawah = paling awal
        raw = " ".join(str(raw).split())
        entry: dict = {"raw": raw[:300]}
        m = _RE_RECEIVED.search(raw)
        if m:
            entry["from"] = m.group(1).rstrip(",;")
            detail = (m.group(2) or "")
            ipm = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", detail)
            if ipm:
                entry["ip"] = ipm.group(1)
            if m.group(3):
                entry["by"] = m.group(3).rstrip(",;")
        hops.append(entry)
    return hops


def _attachments(msg: email.message.Message) -> list[dict]:
    out: list[dict] = []
    for part in msg.walk():
        fname = part.get_filename()
        disp = part.get_content_disposition()
        if not fname and disp != "attachment":
            continue
        payload = b""
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        entry: dict = {
            "name": fname or "(tanpa nama)",
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest() if payload
                      else None,
        }
        low = (fname or "").lower()
        exts = [s for s in Path(low).suffixes]
        entry["extensions"] = exts
        if any(e in _EXEC_EXT for e in exts):
            entry["risk"] = "executable-script"
        elif any(e in _MACRO_EXT for e in exts):
            entry["risk"] = "macro-capable"
        elif any(e in _ARCHIVE_EXT for e in exts):
            entry["risk"] = "archive"
        # ekstensi ganda: dokumen/arsip lalu eksekusi (a.pdf.exe)
        if len(exts) >= 2 and exts[-1] in _EXEC_EXT:
            entry["risk"] = "double-extension"
        out.append(entry)
    return out


def _urls_and_mismatch(msg: email.message.Message) -> tuple[list[str],
                                                            list[dict]]:
    urls: list[str] = []
    mismatches: list[dict] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue
        for u in _RE_URL.findall(content):
            if u not in urls:
                urls.append(u)
        if ctype == "text/html":
            for href, display in _RE_HREF.findall(content):
                plain = _RE_TAG.sub("", display).strip()
                shown = _RE_URL.findall(plain)
                if shown and shown[0].rstrip(".?!,;)") != href.rstrip(
                        ".?!,;)"):
                    mismatches.append({
                        "display": shown[0][:200],
                        "href": href[:200]})
    return urls, mismatches


def triage_file(path: Path, legit: list[str] | None = None) -> dict:
    raw = path.read_bytes()
    if not raw.strip():
        raise ValueError("file kosong")
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    if not msg.keys():
        raise ValueError("tidak ada header RFC5322 yang ter-parse")

    from_addr = email.utils.parseaddr(str(msg.get("From", "")))[1]
    reply_to = email.utils.parseaddr(str(msg.get("Reply-To", "")))[1]
    return_path = str(msg.get("Return-Path", "")).strip()
    from_dom = _domain_of(from_addr)

    findings: list[dict] = []

    # 1. Reply-To mismatch
    if reply_to and from_addr and reply_to != from_addr:
        findings.append({
            "type": "replyto-mismatch", "severity": "high",
            "detail": "Reply-To berbeda dari From (indikasi klasik "
                      "BEC/spoofing)",
            "evidence": {"from": _defang(from_addr),
                         "reply_to": _defang(reply_to)},
        })

    # 2. Return-Path domain mismatch
    rp_dom = _domain_of(return_path.strip("<>"))
    if rp_dom and from_dom and rp_dom != from_dom:
        findings.append({
            "type": "returnpath-mismatch", "severity": "medium",
            "detail": "domain Return-Path berbeda dari domain From "
                      "(bounce domain asing)",
            "evidence": {"from_domain": _defang(from_dom),
                         "returnpath_domain": _defang(rp_dom)},
        })

    # 3. verdict autentikasi TERTULIS di header
    ar_headers = [str(x) for x in (msg.get_all("Authentication-Results")
                                   or [])]
    r_spf = [str(x) for x in (msg.get_all("Received-SPF") or [])]
    verdicts, ar_sources = parse_auth(ar_headers)
    for h in r_spf:
        m = _RE_RECEIVED_SPF.search(h)
        if m and "spf" not in verdicts:
            verdicts["spf"] = m.group(1).lower()
    dmarc_p = None
    for h in ar_headers:
        mp = _RE_DMARC_P.search(h)
        if mp:
            dmarc_p = mp.group(1).lower()
            break

    auth_missing = not verdicts
    if verdicts:
        worst = _worst(verdicts)
        assert worst is not None
        method, verdict = worst
        sev = None
        if verdict == "fail":
            sev = "high"
        elif verdict in ("softfail", "neutral", "none", "permerror",
                         "temperror"):
            sev = "medium"
        if sev:
            findings.append({
                "type": "auth-verdict", "severity": sev,
                "detail": f"hasil autentikasi tertulis: {method}="
                          f"{verdict}",
                "evidence": {"verdicts": verdicts,
                             "dmarc_policy": dmarc_p,
                             "sources": ar_sources[:_UNPARSED_SAMPLE_MAX]},
            })

    # 4. lookalike / homoglyph (butuh --legit)
    if legit and from_dom:
        norm = _normalize_domain(from_dom)
        for target in legit:
            t = target.strip().lower()
            if not t:
                continue
            if from_dom == t:
                continue
            if norm == t:
                findings.append({
                    "type": "lookalike-domain", "severity": "critical",
                    "detail": f"domain From homoglyph dari {t} "
                              "(identik setelah normalisasi confusable)",
                    "evidence": {"from_domain": _defang(from_dom),
                                 "legit": t},
                })
                break
            ratio = 1.0 - _levenshtein(norm, t) / max(len(norm),
                                                      len(t))
            if ratio >= 0.8:
                findings.append({
                    "type": "lookalike-domain", "severity": "high",
                    "detail": f"domain From mirip {t} "
                              f"(rasio kemiripan {ratio:.0%})",
                    "evidence": {"from_domain": _defang(from_dom),
                                 "legit": t,
                                 "similarity": round(ratio, 3)},
                })
                break

    # 5. URL display vs href
    urls, mismatches = _urls_and_mismatch(msg)
    for mm in mismatches[:_UNPARSED_SAMPLE_MAX]:
        findings.append({
            "type": "url-display-mismatch", "severity": "high",
            "detail": "teks tautan memuat URL berbeda dari href "
                      "aktual",
            "evidence": {"display": _defang(mm["display"]),
                         "href": _defang(mm["href"])},
        })

    # 6. lampiran berisiko
    attachments = _attachments(msg)
    for att in attachments:
        risk = att.get("risk")
        if not risk:
            continue
        sev = "critical" if risk == "double-extension" else "high"
        findings.append({
            "type": "dangerous-attachment", "severity": sev,
            "detail": f"lampiran berisiko ({risk}): {att['name'][:80]}",
            "evidence": {"name": att["name"], "size": att["size"],
                         "sha256": att["sha256"],
                         "extensions": att["extensions"]},
        })

    defects = [f"{d.__class__.__name__}" for d in getattr(
        msg, "defects", [])]
    hops = _received_chain(msg)

    out: dict = {
        "schema": SCHEMA,
        "file": str(path),
        "subject": str(msg.get("Subject", ""))[:200],
        "from": _defang(from_addr),
        "to": _defang(str(msg.get("To", ""))[:200]),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "reply_to": _defang(reply_to) if reply_to else None,
        "return_path": _defang(return_path) if return_path else None,
        "x_originating_ip": str(msg.get("X-Originating-IP", "")) or None,
        "hops": len(hops),
        "received_chain": hops,
        "auth_verdicts": verdicts,
        "auth_missing": auth_missing,
        "url_count": len(urls),
        "urls_display": [_defang(u) for u in urls[:50]],
        "attachment_count": len(attachments),
        "attachments": attachments,
        "finding_count": len(findings),
        "findings": findings,
        "meta": {"defects": defects,
                 "legit_domains": [_defang(x) for x in (legit or [])]},
        "note": "semua temuan = LEAD triase header, bukan keputusan "
                "final; verdict auth hanya yang tertulis di header "
                "(bukan verifikasi aktif)",
        "read_only": True,
    }
    if auth_missing:
        out["note"] += ("; Authentication-Results tidak ada — JANGAN "
                        "disimpulkan aman")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase header email (.eml) utk investigasi "
                    "phishing (read-only, NOL jaringan)")
    ap.add_argument("--eml", required=True,
                    help="file email mentah (.eml / hasil Show original)")
    ap.add_argument("--legit", action="append", default=[],
                    help="domain sah utk deteksi lookalike/homoglyph "
                         "(dapat diulang)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.eml)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage_file(path, args.legit or None)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
