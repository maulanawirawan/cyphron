"""ledger — usage ledger per scan (U10): jejak pemakaian append-only.

Setiap scan menambahkan satu baris JSONL (usage-ledger.jsonl di folder
hasil scan) berisi target, mode, otorisasi, ongkos (langkah/request),
dan hasil ringkas. Ledger ini jadi dasar operasional: audit pemakaian
per klien, agregasi ongkos, dan bukti bahwa scan dibatasi budgetnya.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

LEDGER_FILE = "usage-ledger.jsonl"


def record_scan(scan_dir: Path) -> dict:
    """Baca findings.json hasil scan + tambahkan satu baris ledger."""
    scan_dir = Path(scan_dir)
    data = json.loads((scan_dir / "findings.json").read_text(encoding="utf-8"))
    world = data.get("world") or {}
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "target": data.get("target", ""),
        "mode": data.get("mode", ""),
        "authorization": data.get("authorization"),
        "steps": data.get("steps", 0),
        "requests": world.get("request_count", 0),
        "confirmed": len(data.get("confirmed") or []),
        "unconfirmed": len(data.get("unconfirmed") or []),
        "refused_actions": data.get("refused_actions", 0),
        "elapsed_s": data.get("elapsed_s", 0),
    }
    path = scan_dir / LEDGER_FILE
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def summarize(scan_dir: Path) -> dict:
    """Agregat ledger di satu folder (multi-scan ke target yang sama pun ok)."""
    path = Path(scan_dir) / LEDGER_FILE
    rows: list[dict] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    per_target: dict[str, dict] = {}
    for r in rows:
        agg = per_target.setdefault(r.get("target", ""), {
            "scans": 0, "requests": 0, "confirmed": 0, "unconfirmed": 0})
        agg["scans"] += 1
        agg["requests"] += r.get("requests", 0)
        agg["confirmed"] += r.get("confirmed", 0)
        agg["unconfirmed"] += r.get("unconfirmed", 0)
    return {
        "scans": len(rows),
        "requests": sum(r.get("requests", 0) for r in rows),
        "confirmed": sum(r.get("confirmed", 0) for r in rows),
        "unconfirmed": sum(r.get("unconfirmed", 0) for r in rows),
        "per_target": per_target,
        "rows": rows,
    }
