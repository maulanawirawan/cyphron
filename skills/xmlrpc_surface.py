"""[SAFETY: 1-request] xmlrpc-surface — antarmuka XML-RPC terbuka
(CWE-200/916): SATU POST system.listMethods dengan body minimal;
signature respons XML (<methodResponse> + nama method) = antarmuka
hidup -> L2 lead (pingback SSRF / credential probing / user enum
klasik dari sini). 404/bukan-XML = AMAN. Satu endpoint per run
(--path, default /xmlrpc.php).
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
BODY = (b"<?xml version=\"1.0\"?><methodCall><methodName>"
        b"system.listMethods</methodName><params></params></methodCall>")


def probe(url: str, timeout: float = 20.0) -> dict:
    req = urllib.request.Request(url, data=BODY, method="POST",
                                 headers={"User-Agent": UA,
                                          "Content-Type": "text/xml"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "body": r.read(32_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = (e.read(16_000) or b"").decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body}
    except Exception as exc:
        return {"status": None, "error": f"{type(exc).__name__}: {exc}",
                "body": ""}


def audit(url: str, result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    body = result.get("body", "")
    is_xmlrpc = ("<methodResponse" in body
                 and "listMethods" in body)
    if result.get("status") is None:
        rows.append(make_finding(
            tool="xmlrpc-surface", title=f"Fetch failed on {url}",
            severity="info", description=str(result.get("error"))[:300],
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "1-request"}))
        return rows, {"url": url, "error": True}
    if is_xmlrpc:
        rows.append(make_finding(
            tool="xmlrpc-surface",
            title=f"XML-RPC interface open on {url}",
            severity="medium",
            description="Antarmuka XML-RPC merespons system.listMethods "
                        "dengan daftar method — permukaan klasik untuk "
                        "pingback SSRF, credential probing (wp."
                        "getUsersBlogs), dan enumerasi. L2 lead: kelas "
                        "serangan turunannya butuh uji manual dalam "
                        "scope.",
            recommendation="Matikan XML-RPC bila tidak dipakai; bila "
                           "dipakai, batasi method + rate-limit + "
                           "matikan pingback.",
            cwe="CWE-200",
            target_url=url, response=body[:300],
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=2,
            extra={"category": "SURFACE", "safety_class": "1-request"}))
    else:
        rows.append(make_finding(
            tool="xmlrpc-surface",
            title=f"No XML-RPC interface on {url}", severity="info",
            description=f"Respons {result.get('status')} tanpa signature "
                        "XML-RPC — antarmuka tidak hidup (AMAN/"
                        "inventaris).",
            target_url=url, response=body[:200],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "1-request"}))
    return rows, {"url": url, "requests": 1, "open": is_xmlrpc}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--path", default="/xmlrpc.php")
    ap.add_argument("--out", default="xmlrpc_surface_findings.json")
    args = ap.parse_args()
    url = args.url.rstrip("/") + args.path
    result = probe(url)
    rows, meta = audit(url, result)
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    print(f"xmlrpc-surface: {len(rows)} temuan "
          f"(open={meta.get('open', [])}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
