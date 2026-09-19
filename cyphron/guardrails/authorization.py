"""Authorization gate — machine-enforced; protokol lengkap:
.kimchi/guardrails/authorization-protocol.md.

NO valid authorization document -> active/offensive tools are refused and
the run degrades to read-only (passive) mode. This is enforced in code,
not in a prompt: the model (if one is ever plugged into the planner slot)
cannot talk its way past it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlparse

REQUIRED_DOC_FIELDS = ("id", "issued_at", "expires_at", "target", "scope", "authorized_by")
REQUIRED_SCOPE_FIELDS = ("targets", "excluded", "cidr")


@dataclass
class ScopeSpec:
    targets: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    cidr: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, scope: dict) -> "ScopeSpec":
        return cls(
            targets=[str(t).lower() for t in (scope.get("targets") or [])],
            excluded=[str(t).lower() for t in (scope.get("excluded") or [])],
            cidr=[str(c) for c in (scope.get("cidr") or [])],
            ports=[int(p) for p in (scope.get("ports") or [])],
        )

    def check(self, host: str, port: int) -> tuple[bool, str]:
        host_l = (host or "").lower()
        if not host_l:
            return False, "no host in target"
        for exc in self.excluded:
            if self._domain_match(host_l, exc):
                return False, f"host explicitly excluded by scope ({exc})"
        for allowed in self.targets:
            if self._domain_match(host_l, allowed):
                if self.ports and port not in self.ports:
                    return False, f"port {port} not in authorized ports {self.ports}"
                return True, f"in scope (target match: {allowed})"
        try:
            ip = ip_address(host_l)
        except ValueError:
            return False, f"host {host_l} not in scope targets"
        for cidr in self.cidr:
            try:
                if ip in ip_network(cidr, strict=False):
                    if self.ports and port not in self.ports:
                        return False, f"port {port} not in authorized ports {self.ports}"
                    return True, f"in scope (CIDR {cidr})"
            except ValueError:
                continue
        return False, f"IP {host_l} not within scope CIDRs"

    @staticmethod
    def _domain_match(host: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            return host.endswith(pattern[1:]) or host == pattern[2:]
        return host == pattern


@dataclass
class AuthorizationDocument:
    id: str
    issued_at: datetime
    expires_at: datetime
    target_name: str
    scope: ScopeSpec
    authorized_by: str
    restrictions: list[str]
    signature: str
    raw: dict

    @classmethod
    def load(cls, path: Path) -> "AuthorizationDocument":
        doc = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(doc)

    @classmethod
    def from_dict(cls, doc: dict) -> "AuthorizationDocument":
        missing = [f for f in REQUIRED_DOC_FIELDS if f not in doc]
        if missing:
            raise ValueError(f"authorization document missing fields: {missing}")
        scope_raw = doc.get("scope") or {}
        scope = ScopeSpec.from_dict(scope_raw)
        if not (scope.targets or scope.cidr):
            raise ValueError("scope must define targets or CIDR")
        if not doc.get("signature"):
            raise ValueError("authorization document must be signed")
        return cls(
            id=str(doc["id"]),
            issued_at=_parse_dt(doc["issued_at"]),
            expires_at=_parse_dt(doc["expires_at"]),
            target_name=str((doc.get("target") or {}).get("name", "unnamed")),
            scope=scope,
            authorized_by=str((doc.get("authorized_by") or {}).get("name", "unknown")),
            restrictions=[str(r) for r in (doc.get("restrictions") or [])],
            signature=str(doc["signature"]),
            raw=doc,
        )

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.expires_at < now


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class Decision:
    allowed: bool
    mode: str  # "offensive" | "read-only"
    reason: str
    auth_id: str | None = None


class AuthorizationGate:
    """Decides whether a tool with the given risk tags may run against a
    target. Passive tools run in read-only mode without any document;
    anything tagged active/intrusive requires a valid, in-scope document."""

    def __init__(self, doc: AuthorizationDocument | None, now: datetime | None = None):
        self.doc = doc
        self.now = now or datetime.now(timezone.utc)

    def evaluate(self, host: str, port: int, risk_tags: set[str]) -> Decision:
        passive = risk_tags <= {"passive", "local"}
        if self.doc is None:
            if passive:
                return Decision(True, "read-only", "no authorization document: passive checks only")
            return Decision(
                False, "read-only",
                "active tool requested but no authorization document provided",
            )
        if self.doc.is_expired(self.now):
            return Decision(False, "read-only", f"authorization {self.doc.id} expired at {self.doc.expires_at.isoformat()}")
        in_scope, reason = self.doc.scope.check(host, port)
        if not in_scope:
            return Decision(False, "read-only", f"target out of scope: {reason}")
        if passive:
            return Decision(True, "read-only", f"authorized ({self.doc.id}): passive check", self.doc.id)
        blocked = _restriction_block(self.doc.restrictions, risk_tags)
        if blocked:
            return Decision(False, "read-only", f"action restricted by {self.doc.id}: {blocked}")
        return Decision(True, "offensive", f"authorized ({self.doc.id}): active testing in scope", self.doc.id)

    def evaluate_host(self, host: str, port: int,
                      risk_tags: set[str] | None = None) -> Decision:
        """Per-destination scope check for hosts an engine discovers itself
        (sibling subdomains, MX hosts, redirect targets). Unlike evaluate(),
        there is NO passive fast-path: DNS resolution and HTTP to the
        destination are both active operations, so the destination host must
        be in scope no matter how the calling tool is tagged."""
        tags = risk_tags or {"active"}
        if self.doc is None:
            return Decision(False, "read-only",
                            "no authorization document: discovered host is not tested")
        if self.doc.is_expired(self.now):
            return Decision(False, "read-only",
                            f"authorization {self.doc.id} expired at {self.doc.expires_at.isoformat()}")
        in_scope, reason = self.doc.scope.check(host, port)
        if not in_scope:
            return Decision(False, "read-only", f"out of scope: {reason}")
        blocked = _restriction_block(self.doc.restrictions, set(tags))
        if blocked:
            return Decision(False, "read-only", f"action restricted by {self.doc.id}: {blocked}")
        return Decision(True, "offensive", f"in scope ({self.doc.id}): {reason}", self.doc.id)


RESTRICTION_TAGS = {
    "no_dos": {"dos", "flood", "stress"},
    "no_data_exfiltration": {"exfiltration"},
    "no_persistence": {"persistence"},
    "no_aggressive": {"aggressive"},
    "read_only": {"active"},
    # engine ber-tag "external" mengakses layanan/publik di luar target
    # (intel IP, passive DNS, OSINT, crt.sh, wayback, OSV, OOB capture) —
    # dokumen otorisasi bisa melarang seluruh kategori ini
    "no_external_intel": {"external"},
}


def _restriction_block(restrictions: list[str], risk_tags: set[str]) -> str | None:
    now = datetime.now()
    for restriction in restrictions:
        tags = RESTRICTION_TAGS.get(restriction)
        if tags and (risk_tags & tags):
            return restriction
        if restriction == "business_hours_only" and not (8 <= now.hour < 18):
            return "business_hours_only (outside 08:00-18:00)"
    return None


class AuditLog:
    """Tamper-evident, hash-chained log of every authorization decision and
    tool execution (port of the AuthorizationAuditLog in the protocol doc)."""

    def __init__(self):
        self.entries: list[dict] = []
        self._last_hash = self._genesis()

    @staticmethod
    def _genesis() -> str:
        return hashlib.sha256(b"cyphron-audit-genesis").hexdigest()

    def append(self, event: dict) -> dict:
        entry = dict(event)
        entry["previous_hash"] = self._last_hash
        payload = json.dumps(entry, sort_keys=True, default=str).encode()
        entry["hash"] = hashlib.sha256(payload).hexdigest()
        self._last_hash = entry["hash"]
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, str]:
        expected_prev = self._genesis()
        for i, entry in enumerate(self.entries):
            if entry.get("previous_hash") != expected_prev:
                return False, f"chain broken at entry {i}"
            stored = entry.get("hash")
            replay = {k: v for k, v in entry.items() if k != "hash"}
            digest = hashlib.sha256(json.dumps(replay, sort_keys=True, default=str).encode()).hexdigest()
            if stored != digest:
                return False, f"tampered entry {i}"
            expected_prev = stored
        return True, f"{len(self.entries)} entries verified"


def host_port_of(target: str) -> tuple[str, int]:
    """Extract (host, port) from a URL or local path target."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def is_local_path(target: str) -> bool:
    return not _URL_RE.match(target)
