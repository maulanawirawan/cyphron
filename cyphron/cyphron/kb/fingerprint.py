"""fingerprint -> CPE 2.3 — penerjemah hasil census/banner menjadi CPE.

Input: string teknologi apa pun (header Server/X-Powered-By, meta generator,
catatan census). Output: daftar CpeMatch (CPE 2.3 + versi + bukti sumber).

Zero-FP: regex ketat dari cpe_map.yaml; tanpa versi -> CPE version="*" dan
flag versioned=False (cve_matcher TIDAK mengklaim CVE dari ini, hanya note).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .. import yamlite

CPE_MAP_FILE = Path(__file__).resolve().parent / "cpe_map.yaml"


@dataclass
class CpeMatch:
    cpe23: str
    vendor: str
    product: str
    version: str  # "*" bila versi tidak diketahui
    versioned: bool
    mapping_id: str
    source: str  # string mentah yang menumbuhkan CPE ini
    note_only: bool = False


def load_cpe_map(path: Path | None = None) -> list[dict]:
    text = (path or CPE_MAP_FILE).read_text(encoding="utf-8")
    data = yamlite.parse(text)
    mappings = data.get("mappings") or []
    return [m for m in mappings if isinstance(m, dict)]


def cpe23_str(part: str, vendor: str, product: str, version: str) -> str:
    return (f"cpe:2.3:{part}:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*")


def fingerprints_from_world(world) -> list[str]:
    """Kumpulkan string kandidat fingerprint dari WorldModel:
    kunci+nilai technologies (mis. 'Server: nginx/1.24.0')."""
    texts: list[str] = []
    for key, value in (getattr(world, "technologies", None) or {}).items():
        texts.append(str(key))
        if value:
            texts.append(str(value))
    return texts


def to_cpe(texts, mappings: list[dict] | None = None) -> list[CpeMatch]:
    """Terjemahkan string -> CPE unik (vendor, product, version)."""
    mappings = mappings if mappings is not None else load_cpe_map()
    found: dict[tuple, CpeMatch] = {}
    for text in texts:
        if not isinstance(text, str) or not text.strip():
            continue
        for m in mappings:
            pattern = m.get("pattern") or ""
            try:
                rx = re.compile(pattern)
            except re.error:
                continue
            hit = rx.search(text)
            if not hit:
                continue
            version = hit.group(1) if (hit.groups() and hit.group(1)) else "*"
            note_only = bool(m.get("note_only"))
            vendor = str(m.get("vendor") or "")
            product = str(m.get("product") or "")
            part = str(m.get("part") or "a")
            cm = CpeMatch(
                cpe23=cpe23_str(part, vendor, product, version),
                vendor=vendor, product=product, version=version,
                versioned=(version != "*"), mapping_id=str(m.get("id") or ""),
                source=text[:160], note_only=note_only,
            )
            key = (cm.vendor, cm.product, cm.version)
            if key not in found:
                found[key] = cm
    return sorted(found.values(),
                  key=lambda c: (c.vendor, c.product, c.version))
