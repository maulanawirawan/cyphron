"""Cyphron Core — standalone AI pentest agent runtime.

Zero third-party dependencies. Zero LLM providers (reasoning is
deterministic; an LLM planner slot exists but is deliberately unplugged).
Loads the .kimchi knowledge pack (65 skills, guardrails, knowledge base)
and runs an authorization-gated pentest loop with built-in engines.
"""

__version__ = "0.1.0"
KIMCHI_DIRNAME = ".cyphron"  # renamed from .kimchi (legacy name kept in var for compat)
