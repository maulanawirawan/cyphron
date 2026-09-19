"""Skill registry: loads the .kimchi skill pack and retrieves top-k skills
for a goal/query. Deterministic scoring (trigger match + keyword overlap);
an embedding/RAG backend can replace `retrieve` later without touching the
orchestrator."""

from __future__ import annotations

import re

from ..config import Config, SkillMeta

_WORD = re.compile(r"[a-z0-9]+")


class SkillRegistry:
    def __init__(self, config: Config):
        self.config = config
        self.skills: list[SkillMeta] = [s for s in config.skills if s.path is not None]

    def __len__(self) -> int:
        return len(self.skills)

    def inventory(self) -> list[tuple[str, str, str]]:
        return [(s.id, s.name, s.mode) for s in self.skills]

    def retrieve(self, query: str, top_k: int = 3) -> list[tuple[SkillMeta, float]]:
        q = query.lower()
        q_words = set(_WORD.findall(q))
        scored: list[tuple[SkillMeta, float]] = []
        for skill in self.skills:
            score = 0.0
            for trigger in skill.triggers:
                t = trigger.lower()
                if " " in t:
                    if t in q:
                        score += 3.0
                elif t in q_words:
                    score += 2.5
                else:
                    # partial word containment for short technical triggers
                    if len(t) >= 4 and t in q:
                        score += 1.0
            title_words = set(_WORD.findall(skill.name.lower()))
            score += 0.5 * len(q_words & title_words)
            hint_text = " ".join(skill.activation_hints).lower()
            if hint_text:
                hint_words = set(_WORD.findall(hint_text))
                score += 0.2 * len(q_words & hint_words)
            if score > 0:
                # lower priority number = more important; small tie-break bonus
                score += (4 - min(skill.priority, 4)) * 0.05
                scored.append((skill, round(score, 3)))
        scored.sort(key=lambda pair: (-pair[1], pair[0].priority, pair[0].id))
        return scored[:top_k]

    def methodology_excerpt(self, skill: SkillMeta, max_chars: int = 900) -> str:
        """Extract the METHODOLOGY section (headline lines) for citations."""
        lines = skill.content.splitlines()
        inside = False
        keep: list[str] = []
        for line in lines:
            if line.startswith("## "):
                if inside:
                    break
                inside = "methodology" in line.lower()
                continue
            if inside:
                stripped = line.strip()
                if stripped.startswith(("###", "- ", "* ")) or (keep and stripped == ""):
                    keep.append(stripped)
                elif keep and stripped:
                    keep.append(stripped)
                if sum(len(k) for k in keep) > max_chars:
                    break
        text = "\n".join(k for k in keep if k).strip()
        return text[:max_chars]
