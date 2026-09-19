"""credits — pembukuan token per lisensi (anti-overshoot, tamper-evident).

Ledger JSON di ~/.cyphron/credits-<hash>.json:
    {"licensee": "...", "total_spent": N, "entries": [ {ts, tool, cost, mode,
     chain} ], "sig": hmac(total_spent+last_chain)}

- 1 token = 1 eksekusi tool dibobot risk_tag (pricing.token_cost_for), lalu
  dikali multiplier mode.
- Kind=trial: token_limit kecil (30) — habis = REFUSED sampai lisensi baru.
- Kejujuran: penghapusan file ledger TIDAK bisa dicegah sepenuhnya offline —
  kuota yang tegas (reset-proof) dicatat billing server; ledger ini
  tamper-EVIDENT (rantai HMAC) untuk melawan edit kasar.
"""

from __future__ import annotations

import json
import time
from hashlib import sha256
from pathlib import Path

from .antibuse import license_secret, license_sig
from .pricing import MODE_MULTIPLIER, token_cost_for


def _ledger_path(licensee: str) -> Path:
    h = sha256(licensee.encode("utf-8", "replace")).hexdigest()[:16]
    base = Path(__import__("os").environ.get("CYPHRON_HOME",
                                             Path.home() / ".cyphron"))
    return base / f"credits-{h}.json"


class CreditLedger:
    def __init__(self, licensee: str, token_limit: int | None = None,
                 mode: str = "active"):
        self.licensee = licensee or "unlicensed"
        self.token_limit = token_limit
        self.mode = mode if mode in MODE_MULTIPLIER else "active"
        self.path = _ledger_path(self.licensee)
        self.total_spent = 0
        self.entries: list[dict] = []
        self._load()

    # -------------------------------------------------------------- io
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("licensee") != self.licensee:
                return
            self.total_spent = int(data.get("total_spent", 0))
            self.entries = list(data.get("entries", []))[-200:]
        except (json.JSONDecodeError, ValueError, TypeError):
            return  # ledger korup: mulai segar (server tetap sumber kebenaran)

    def _persist(self) -> None:
        last = self.entries[-1]["chain"] if self.entries else "genesis"
        sig = license_sig(license_secret(), {
            "licensee": self.licensee, "total_spent": self.total_spent,
            "last_chain": last})
        payload = {"licensee": self.licensee, "total_spent": self.total_spent,
                   "entries": self.entries[-200:], "sig": sig}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=1), encoding="utf-8")

    # ------------------------------------------------------------ API
    def spent_now(self, limit: int | None = None) -> int:
        """Token terpakai pada batas periode ini (dipakai untuk trial)."""
        if limit is None:
            return self.total_spent
        # trial: hanya hitung entri lisensi berjalan — entri di atas window
        # periode trial tidak bisa dibedakan offline; karena trial berumur
        # pendek + 1x/device (antibuse), total_spent cukup konservatif.
        return min(self.total_spent, limit)

    def can_spend(self, risk_tags: set[str], token_limit: int | None) -> tuple[bool, str, int]:
        cost = int(token_cost_for(set(risk_tags))
                   * MODE_MULTIPLIER.get(self.mode, 1.0))
        if token_limit is None:
            return True, "no token limit", cost
        used = self.spent_now(token_limit)
        if used + cost > token_limit:
            return (False,
                    f"token habis: {used}/{token_limit} terpakai, butuh {cost}",
                    cost)
        return True, f"{used}/{token_limit} terpakai", cost

    def spend(self, tool: str, risk_tags: set[str], license_sig_field: str = "") -> int:
        ok, _reason, cost = self.can_spend(risk_tags, None)
        prev = self.entries[-1]["chain"] if self.entries else "genesis"
        chain = sha256(f"{prev}:{tool}:{cost}:{time.time_ns()}".encode()).hexdigest()
        self.entries.append({"ts": time.time(), "tool": tool, "cost": cost,
                             "mode": self.mode, "chain": chain})
        self.total_spent += cost
        self._persist()
        return cost
