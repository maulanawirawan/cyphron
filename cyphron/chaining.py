"""chaining — Attack Chain Composer (Cyphron Intelligence Fabric).

Scanner biasa melaporkan temuan satu-per-satu. Composer mencari komposisi:
temuan A yang membuka jalan bagi temuan B yang bersama-sama mencapai target
bernilai — lalu menilai impact GABUNGAN mereka, bukan impact terbesar
per-individu. Deterministik, rule-based, zero-dependency (stdlib only).

Prinsip (dari desain engine Cyphron):
  - rantai HANYA dibentuk dari temuan yang sudah tervalidasi (status
    confirmed) — komposisi tidak boleh menaikkan severity temuan yang
    tidak terbukti;
  - rule prereq -> enables eksplisit (bukan "sekadar ada di host sama");
  - lintas-host tidak dirantai kecuali rule mengizinkan;
  - eskalasi severity dibatasi satu tingkat per rule dan dijelaskan
    rationale-nya di output (audit-friendly).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .findings import Finding, SEVERITY_ORDER

__all__ = ["Chain", "compose", "classify"]

_ORDER = ["info", "low", "medium", "high", "critical"]


def _sev_ge(a: str, b: str) -> bool:
    """True bila severity `a` >= `b` (_ORDER urut dari info ke critical)."""
    return _ORDER.index(a) >= _ORDER.index(b)


def _max_sev(sevs: list[str]) -> str:
    return min(sevs, key=lambda s: SEVERITY_ORDER[s]) if sevs else "info"


def _esc(sev: str) -> str:
    """Eskalasi SATU tingkat: info→low→medium→high→critical (cap di critical)."""
    return _ORDER[min(_ORDER.index(sev) + 1, len(_ORDER) - 1)]


# ----------------------------------------------------------- capability classes
def classify(f: Finding) -> list[str]:
    """Kemampuan serangan yang dibuka oleh SATU temuan (bisa >1)."""
    tags: list[str] = []
    cwe = f.cwe or ""
    title = (f.title or "").lower()
    tool = (f.tool or "").lower()
    if cwe == "CWE-200" or "user enumeration" in title or "user enum" in title:
        tags.append("user-enum")
    if cwe == "CWE-307" or "lockout" in title or "rate limit" in title:
        tags.append("no-lockout")
    if cwe in ("CWE-209", "CWE-489") or "debug" in title and "page" in title:
        tags.append("debug-disclosure")
    if cwe == "CWE-798" or ("credential" in title and ("hardcoded" in title or "basic auth" in title)):
        tags.append("hardcoded-cred")
    if cwe == "CWE-918" or "ssrf" in title:
        tags.append("ssrf")
    if "multicall" in title or ("amplification" in title and "xmlrpc" in tool):
        tags.append("cred-amplification")
    if cwe in ("CWE-639", "CWE-284") or "idor" in title or "bola" in title or "authz" in title:
        tags.append("broken-authz")
    if "sourcemap" in title or (cwe == "CWE-540" and "map" in title):
        tags.append("source-disclosure")
    if cwe == "CWE-532" or "debug.log" in title:
        tags.append("log-disclosure")
    if cwe in ("CWE-79", "CWE-89", "CWE-94"):
        tags.append("injection-primitive")
    if "takeover" in title:
        tags.append("takeover")
    return tags


def _host(f: Finding) -> str:
    if f.target_url:
        return urlsplit(f.target_url if "//" in f.target_url else "//" + f.target_url).hostname \
            or f.target_url
    if f.file_path:
        return "repo:" + f.file_path.split("/")[0].split("\\")[0]
    return "unknown"


# ------------------------------------------------------------------ chain rules
@dataclass
class ChainRule:
    rule_id: str
    name: str
    requires: list[str]              # capability classes; tiap class harus
                                     # diwakili >=1 temuan BERBEDA
    same_host: bool = True
    escalate_to: str = "high"        # combined severity minimal rantai
    rationale: str = ""


RULES: list[ChainRule] = [
    ChainRule(
        rule_id="CH-spray-pipeline",
        name="Credential spraying pipeline (user enum + no lockout)",
        requires=["user-enum", "no-lockout"],
        escalate_to="high",
        rationale=("Usernames are public (enumeration) and the login endpoint accepts "
                   "unlimited failed attempts (no lockout/rate limit): together they form "
                   "an unrestricted password-spraying pipeline."),
    ),
    ChainRule(
        rule_id="CH-spray-amplified",
        name="Amplified credential attack (user enum + request-level amplification)",
        requires=["user-enum", "cred-amplification"],
        escalate_to="high",
        rationale=("Enumerable usernames combined with a request-level amplification "
                   "primitive let an attacker batch authentication checks, multiplying "
                   "guessing speed by the batch size."),
    ),
    ChainRule(
        rule_id="CH-debug-to-creds",
        name="Debug disclosure -> credential reuse",
        requires=["debug-disclosure", "hardcoded-cred"],
        escalate_to="high",
        rationale=("Verbose debug output discloses internal structure while hardcoded "
                   "credentials are exposed; combined they turn an information leak into "
                   "a working entry point."),
    ),
    ChainRule(
        rule_id="CH-enum-to-authz",
        name="Enumeration -> broken authorization probe",
        requires=["user-enum", "broken-authz"],
        escalate_to="high",
        rationale=("Known usernames make broken-authorization endpoints directly "
                   "exploitable (impersonation via predictable identifiers)."),
    ),
    ChainRule(
        rule_id="CH-source-to-cred",
        name="Source disclosure -> credential reuse",
        requires=["source-disclosure", "hardcoded-cred"],
        escalate_to="high",
        rationale=("Recovered source (sourcemaps) plus exposed credentials yield a "
                   "complete map of where the credentials work."),
    ),
]


@dataclass
class Chain:
    chain_id: str
    name: str
    rule_id: str
    steps: list[str]                 # finding ids (urut sesuai requires)
    hosts: list[str]
    combined_severity: str
    rationale: str

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id, "name": self.name, "rule_id": self.rule_id,
            "steps": self.steps, "hosts": self.hosts,
            "combined_severity": self.combined_severity, "rationale": self.rationale,
        }


def compose(findings: list[Finding], rules: list[ChainRule] | None = None) -> list[Chain]:
    """Gabungkan temuan confirmed menjadi rantai. Deterministik: urut rule_id,
    tiap rule maksimal SATU rantai per host (dedupe langkah)."""
    rules = rules if rules is not None else RULES
    confirmed = [f for f in findings if f.status == "confirmed"]
    chains: list[Chain] = []
    for rule in sorted(rules, key=lambda r: r.rule_id):
        # indeks temuan per capability class
        by_class: dict[str, list[Finding]] = {}
        for f in confirmed:
            for tag in classify(f):
                by_class.setdefault(tag, []).append(f)
        if not all(c in by_class for c in rule.requires):
            continue
        # bentuk rantai per host (atau lintas host bila rule mengizinkan)
        pools: dict[str, list[Finding]] = {}
        for c in rule.requires:
            for f in by_class[c]:
                h = _host(f) if rule.same_host else "*"
                pools.setdefault((c, h), []).append(f)
        hosts = sorted({(_host(f) if rule.same_host else "*") for c in rule.requires
                        for f in by_class[c]})
        for h in hosts:
            steps: list[Finding] = []
            used: set[str] = set()
            ok = True
            for c in rule.requires:
                pick = next((f for f in pools.get((c, h), [])
                             if f.id not in used), None)
                if pick is None:
                    ok = False
                    break
                used.add(pick.id)
                steps.append(pick)
            if not ok:
                continue
            step_sevs = [s.severity for s in steps]
            combined = _max_sev(step_sevs)
            # Eskalasi maksimal SATU tingkat di atas bukti individu (invarian
            # docstring) — rule yang minta lompatan lebih hanya naik satu tingkat.
            if _sev_ge(rule.escalate_to, combined):
                combined = _esc(combined)
            chains.append(Chain(
                chain_id=f"{rule.rule_id}:{h}",
                name=rule.name, rule_id=rule.rule_id,
                steps=[s.id for s in steps],
                hosts=[h] if h != "*" else sorted({_host(s) for s in steps}),
                combined_severity=combined,
                rationale=rule.rationale,
            ))
    # dedupe chain_id (host sama bisa tervalidasi dua kali lewat dua rule set)
    out: dict[str, Chain] = {}
    for c in chains:
        out.setdefault(c.chain_id, c)
    return sorted(out.values(), key=lambda c: c.chain_id)
