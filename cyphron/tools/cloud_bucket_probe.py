"""cloud_bucket_probe — cek akses listing bucket cloud DARI INTEL NAMA
(CWE-730, high). BUKAN sweep/brute-force nama bucket.

Sumber nama: args.names (dari census subdomain, OSINT, pattern organisasi)
— dibatasi 8; provider: s3 / gcs / azure (default s3+gcs).
Bukti per provider:
  - S3 : body XML memuat <ListBucketResult = LISTING ANONIM TERBUKA;
         'AccessDenied' = tertutup (bukan temuan); 'NoSuchBucket' = tidak ada.
  - GCS: JSON kind storage#objects + items = listing terbuka; 403 = tertutup.
FP-guard: 1 GET per (nama, provider); hanya marker provider-spesifik yang
dihitung; cease-on-data (stop di listing pertama); konten key TIDAK
diunduh/diredaksi (nama file saja, maks 5).
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


def _urls(provider: str, name: str) -> str:
    if provider == "s3":
        return f"https://{name}.s3.amazonaws.com/"
    if provider == "gcs":
        return f"https://storage.googleapis.com/storage/v1/b/{name}/o"
    if provider == "azure":
        return f"https://{name}.blob.core.windows.net/?comp=list&restype=container"
    return ""


class CloudBucketProbeTool(Tool):
    name = "cloud_bucket_probe"
    description = ("Cek listing anonim bucket S3/GCS/Azure dari daftar nama "
                   "intel (bukan sweep). cease-on-data, nama key direstriksi.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        names = [str(n).strip().lower() for n in (args.get("names") or [])
                 if str(n).strip()][:8]
        providers = [p for p in (args.get("providers") or ["s3", "gcs"])
                     if p in ("s3", "gcs", "azure")]
        if not names or not providers:
            return ToolResult(tool=self.name, ok=False,
                              error="args.names (dari intel) + providers wajib")
        data: dict = {"names": names, "providers": providers, "checks": []}
        findings: list[Finding] = []
        for name in names:
            for prov in providers:
                if ctx.world.request_count >= ctx.max_requests or findings:
                    break  # cease-on-data
                url = _urls(prov, name)
                try:
                    ctx.throttle()
                    st, _h, body, _ms = http_engine.http_get(
                        url, timeout=ctx.timeout_s)
                except Exception as e:
                    data["checks"].append({"name": name, "provider": prov,
                                           "error": type(e).__name__})
                    continue
                ctx.world.request_count += 1
                low = body.lower()
                verdict = "closed-or-unknown"
                if prov == "s3" and "<listbucketresult" in low:
                    verdict = "public-listing"
                elif prov == "gcs" and '"kind": "storage#objects"' in low:
                    verdict = "public-listing"
                elif prov == "azure" and "<enumerationresults" in low:
                    verdict = "public-listing"
                elif "nosuchbucket" in low or '"not found"' in low \
                        or st == 404:
                    verdict = "no-such-bucket"
                elif st == 403 or "accessdenied" in low or "denied" in low:
                    verdict = "denied"
                sample = re.findall(r"<Key>([^<]{1,60})</Key>|"
                                    r"\"name\":\s*\"([^\"]{1,60})\"", body)[:5]
                sample = [a or b for a, b in sample]
                data["checks"].append({"name": name, "provider": prov,
                                       "status": st, "verdict": verdict,
                                       "keys_sample_count": len(sample)})
                if verdict == "public-listing":
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Cloud bucket listing public: {name} ({prov})",
                        severity="high", cwe="CWE-730",
                        description=(
                            f"Bucket '{name}' ({prov}) mengizinkan LISTING "
                            f"anonim: nama objek terbaca tanpa kredensial "
                            f"({len(sample)} contoh key terlihat). Nama file "
                            f"sering membocorkan struktur data (backup, "
                            f"invoice, PI). cease-on-data: tidak ada objek "
                            f"yang diunduh; hanya nama direstriksi."),
                        recommendation=(
                            "Matikan public ACL/iam; block public access; "
                            "prefix-signing untuk akses; audit policy "
                            "bucket."),
                        target_url=url,
                        request=f"GET {url}",
                        response=f"status={st}; verdict=public-listing; "
                                 f"keys_sample={sample[:3]} (direstriksi)",
                        confidence=0.9, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
