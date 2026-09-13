"""kb_sync — pustakawan Cyphron: unduh/perbarui + verifikasi Knowledge Base.

Sumber (semua stdlib, tanpa git wajib):
- nuclei : tarball HEAD repo projectdiscovery/nuclei-templates -> kb/data/nuclei/
- nvd    : feed JSON 1.1 per tahun (nvdcve-1.1-<tahun>.json.gz) -> kb/data/nvd/
- edb    : files_exploits.csv exploitdb -> kb/data/edb/

Aturan:
- Setiap unduhan diverifikasi (gzip valid + sha256 dicatat di manifest).
- Gagal jaringan = pesan jelas, KB lama UTUH (swap atomik: ekstrak ke tmp,
  hapus lama hanya SETELAH salinan baru utuh).
- Tanpa jaringan sama sekali: sync() tidak pernah melempar untuk kegagalan
  per-sumber; hasil error tercatat di manifest["errors"] (CLI yang menampilkan).
"""

from __future__ import annotations

import gzip
import io
import json
import shutil
import tarfile
import urllib.request
from pathlib import Path

from .paths import merge_manifest, resolve_kb_dir, sha256_bytes

SOURCES = ("nuclei", "nvd", "edb")

NUCLEI_TARBALL_URL = ("https://codeload.github.com/projectdiscovery/"
                      "nuclei-templates/tar.gz/refs/heads/main")
NVD_FEED_URL = ("https://nvd.nist.gov/feeds/json/cve/1.1/"
                "nvdcve-1.1-{year}.json.gz")
EDB_CSV_URL = ("https://raw.githubusercontent.com/offensive-security/"
               "exploitdb/main/files_exploits.csv")
DEFAULT_YEARS = range(2018, 2027)


class KbSyncError(RuntimeError):
    """Kegagalan fatal kb_sync (bukan gagal jaringan per-sumber)."""


def _fetch(url: str, timeout: float = 180.0) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read()


def _swap_dir(final: Path, tmp: Path) -> None:
    """Ganti isi folder final dengan tmp secara aman (lama tetap utuh bila
    ekstraksi gagal — pemanggil memanggil ini hanya setelah sukses)."""
    if final.exists():
        shutil.rmtree(final)
    tmp.rename(final)


def sync_nuclei(kb_dir: Path, fetch=_fetch, timeout: float = 180.0) -> dict:
    blob = fetch(NUCLEI_TARBALL_URL, timeout)
    tmp = kb_dir / ".tmp-nuclei"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        root_prefix = None
        for member in tar.getmembers():
            if not member.isfile():
                continue
            top = member.name.split("/", 1)
            if len(top) != 2:
                continue  # entri level-akar repo (README dll di subfolder)
            if root_prefix is None:
                root_prefix = top[0]
            rel = member.name[len(root_prefix) + 1:]
            dest = tmp / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is not None:
                dest.write_bytes(src.read())
    count = sum(1 for _ in tmp.rglob("*") if _.is_file())
    _swap_dir(kb_dir / "nuclei", tmp)
    return {"origin": NUCLEI_TARBALL_URL, "sha256": sha256_bytes(blob),
            "files": count,
            "summary": f"{count} template/berkas"}


def sync_nvd(kb_dir: Path, fetch=_fetch, timeout: float = 180.0,
             years=None) -> dict:
    years = list(years if years is not None else DEFAULT_YEARS)
    out_dir = kb_dir / "nvd"
    out_dir.mkdir(parents=True, exist_ok=True)
    total_cve = 0
    fetched_years = []
    for year in years:
        blob = fetch(NVD_FEED_URL.format(year=year), timeout)
        raw = gzip.decompress(blob)  # verifikasi integritas gzip
        data = json.loads(raw.decode("utf-8", errors="replace"))
        total_cve += len(data.get("CVE_Items", []))
        (out_dir / f"nvdcve-1.1-{year}.json.gz").write_bytes(blob)
        fetched_years.append(year)
    result = {"origin": NVD_FEED_URL.format(year=f"{years[0]}..{years[-1]}"),
              "years": fetched_years, "cves": total_cve,
              "summary": f"{len(fetched_years)} feed ({years[0]}-{years[-1]}), "
                         f"{total_cve} CVE"}
    # bangun indeks CPE<->CVE untuk cve_matcher (gagal build = feed tetap ada)
    from . import nvd_sqlite
    built = nvd_sqlite.build_sqlite(kb_dir)
    if "error" not in built:
        result["sqlite"] = {"cves": built["cves"],
                            "cpe_rows": built["cpe_rows"],
                            "db": built["db"]}
        result["summary"] += f"; cpe.sqlite {built['cpe_rows']} CPE"
    return result


def sync_edb(kb_dir: Path, fetch=_fetch, timeout: float = 180.0) -> dict:
    blob = fetch(EDB_CSV_URL, timeout)
    text = blob.decode("utf-8", errors="replace")
    rows = max(0, sum(1 for line in text.splitlines() if line.strip()) - 1)
    out = kb_dir / "edb" / "files_exploits.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    return {"origin": EDB_CSV_URL, "sha256": sha256_bytes(blob),
            "rows": rows, "summary": f"{rows} entri exploit publik"}


def sync(source: str = "all", kb_dir: Path | str | None = None,
         years=None, fetch=_fetch, timeout: float = 180.0) -> dict:
    """Sinkron KB; gagal per-sumber dicatat, tidak melempar exception."""
    if source == "all":
        wanted = list(SOURCES)
    elif source in SOURCES:
        wanted = [source]
    else:
        raise KbSyncError(f"sumber tidak dikenal: {source!r}")
    d = resolve_kb_dir(kb_dir)
    d.mkdir(parents=True, exist_ok=True)
    updates: dict = {}
    errors: list[str] = []
    jobs = {"nuclei": lambda: sync_nuclei(d, fetch, timeout),
            "nvd": lambda: sync_nvd(d, fetch, timeout, years),
            "edb": lambda: sync_edb(d, fetch, timeout)}
    for name in wanted:
        try:
            updates[name] = jobs[name]()
        except Exception as exc:  # jaringan/format — catat, lanjut
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
    manifest = merge_manifest(d, updates, errors)
    manifest["ok"] = not errors and bool(updates)
    if not updates and errors:
        manifest["hint"] = ("semua sumber gagal — cek jaringan; KB lama "
                            "tetap dipakai")
    return manifest
