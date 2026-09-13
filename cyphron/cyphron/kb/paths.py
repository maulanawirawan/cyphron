"""Lokasi Knowledge Base + manifest versi (hash, jumlah, asal unduhan)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def default_kb_dir() -> Path:
    """Folder data KB default: cyphron/kb/data/ (gitignored)."""
    return Path(__file__).resolve().parent / "data"


def resolve_kb_dir(kb_dir: Path | str | None = None) -> Path:
    return Path(kb_dir) if kb_dir else default_kb_dir()


def manifest_path(kb_dir: Path | str | None = None) -> Path:
    return resolve_kb_dir(kb_dir) / "manifest.json"


def load_manifest(kb_dir: Path | str | None = None) -> dict:
    p = manifest_path(kb_dir)
    if not p.exists():
        return {"sources": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"sources": {}}
    if not isinstance(data, dict) or not isinstance(data.get("sources"), dict):
        return {"sources": {}}
    return data


def write_manifest(kb_dir: Path, manifest: dict) -> Path:
    kb_dir.mkdir(parents=True, exist_ok=True)
    p = manifest_path(kb_dir)
    p.write_text(json.dumps(manifest, indent=1, ensure_ascii=False),
                 encoding="utf-8")
    return p


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merge_manifest(kb_dir: Path, updates: dict, errors: list[str] | None = None) -> dict:
    """Ambil manifest lama, perbarui hanya sumber yang sukses disinkron."""
    import datetime as _dt

    manifest = load_manifest(kb_dir)
    manifest.setdefault("sources", {}).update(updates)
    manifest["errors"] = errors or []
    if updates:
        manifest["synced_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    p = write_manifest(kb_dir, manifest)
    manifest["manifest_path"] = str(p)
    return manifest
