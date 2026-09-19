"""Load the .cyphron knowledge pack (agent-config.yaml + skills)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import KIMCHI_DIRNAME, yamlite


def default_kimchi_dir() -> Path:
    env = os.environ.get("CYPHRON_HOME")
    if env:
        return Path(env).resolve()
    # cyphron/config.py -> paket cyphron -> project root (root repo)
    project = Path(__file__).resolve().parents[1]
    # pack hidup di project root; layout lama (pack satu level di atas
    # project) tetap didukung sebagai fallback
    candidates = (project / KIMCHI_DIRNAME, project.parent / KIMCHI_DIRNAME)
    for cand in candidates:
        if (cand / "agent-config.yaml").is_file():
            return cand
    return candidates[0]


@dataclass
class SkillMeta:
    id: str
    name: str
    file: str
    triggers: list[str] = field(default_factory=list)
    priority: int = 3
    mode: str = "defensive"
    path: Path | None = None
    content: str = ""
    activation_hints: list[str] = field(default_factory=list)
    title: str = ""

    def summary(self) -> str:
        return f"Skill {self.id} — {self.name}"


@dataclass
class Config:
    kimchi_dir: Path
    agent_name: str = "Cyphron"
    agent_version: str = "0"
    description: str = ""
    skills: list[SkillMeta] = field(default_factory=list)
    knowledge: dict[str, str] = field(default_factory=dict)
    guardrails: dict[str, str] = field(default_factory=dict)
    custom_skills_dir: str = "ferments/"
    raw: dict = field(default_factory=dict)

    def knowledge_path(self, key: str) -> Path:
        return self.kimchi_dir / self.knowledge[key]


def load(kimchi_dir: Path | None = None) -> Config:
    kd = (kimchi_dir or default_kimchi_dir()).resolve()
    cfg_path = kd / "agent-config.yaml"
    if not cfg_path.exists():
        raise FileNotFoundError(f"agent-config.yaml not found under {kd}")
    raw = yamlite.parse(cfg_path.read_text(encoding="utf-8"))

    agent = raw.get("agent") or {}
    cfg = Config(kimchi_dir=kd, raw=raw)
    cfg.agent_name = agent.get("name", "Cyphron")
    cfg.agent_version = str(agent.get("version", "0"))
    cfg.description = agent.get("description", "") or ""

    for s in raw.get("skills") or []:
        meta = SkillMeta(
            id=str(s.get("id", "")),
            name=str(s.get("name", "")),
            file=str(s.get("file", "")),
            triggers=[str(t) for t in (s.get("triggers") or [])],
            priority=int(s.get("priority", 3)),
            mode=str(s.get("mode", "defensive")),
        )
        p = kd / meta.file
        if p.exists():
            meta.path = p
            meta.content = p.read_text(encoding="utf-8", errors="replace")
            meta.title = _first_heading(meta.content) or meta.name
            meta.activation_hints = _when_to_activate(meta.content)
        cfg.skills.append(meta)

    knowledge = raw.get("knowledge") or {}
    cfg.knowledge = {k: str(v) for k, v in knowledge.items()}
    guardrails = raw.get("guardrails") or {}
    cfg.guardrails = {k: str(v) for k, v in guardrails.items() if isinstance(v, str)}
    ext = raw.get("extensions") or {}
    cfg.custom_skills_dir = str(ext.get("custom_skills_dir", "ferments/"))
    return cfg


def _first_heading(md: str) -> str | None:
    for line in md.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
        if line.strip():
            break
    return None


def _when_to_activate(md: str) -> list[str]:
    """Extract bullet lines from the WHEN TO ACTIVATE section (if present)."""
    hints: list[str] = []
    inside = False
    for line in md.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            inside = "when to activate" in stripped.lower()
            continue
        if inside and stripped.startswith(("- ", "* ")):
            hints.append(stripped[2:].strip())
    return hints
