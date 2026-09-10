"""Default tool registry — Cyphron's built-in engines (own code only)."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolRegistry, ToolResult, redact
from .auth_probe import AuthProbeTool
from .browser_engine import BrowserEngineTool
from .code_audit import CodeAuditTool
from .crawler import CrawlerTool
from .deep_probe import DeepProbeTool
from .dir_probe import DirProbeTool
from .debug_page import DebugPageTool
from .email_probe import EmailProbeTool
from .fuzz_engine import FuzzEngineTool
from .js_cred_sweep import JsCredSweepTool
from .http_probe import HttpProbeTool
from .load_probe import LoadProbeTool
from .liveness_probe import LivenessProbeTool
from .method_audit import MethodAuditTool
from .redirect_probe import RedirectProbeTool
from .sca_probe import ScaProbeTool
from .wp_probe import WpProbeTool
from .roadmap_batch2 import HeaderPolicyTool, WsProbeTool
from .roadmap_batch3 import (
    CacheDecTool,
    CtLogTool,
    IdSeqTool,
    JsonInjTool,
    OAuthTool,
    PuzzleTool,
    SmuggleTool,
    WaybackTool,
)
from .roadmap_batch4 import (
    ApiVerTool,
    CtaConfTool,
    DkimProbeTool,
    GqlAliasTool,
    GqlBatchTool,
    GqlDepthTool,
    PaginationTool,
    SmtpProbeTool,
    SortFilterTool,
    VerbOverrideTool,
)
from .roadmap_batch5 import (
    CssInjectionTool,
    DomClobberTool,
    JwtCrackTool,
    JwtHeaderTool,
    ProtoClientTool,
    ProtoServerTool,
)
from .roadmap_batch6 import (
    ClickjackTool,
    DomXssTool,
    MqMgmtTool,
    Sourcemap2Tool,
)
from .roadmap_batch7 import BolaTool, PrivMatrixTool
from .roadmap_bounty import AuthzBypassTool, LlmProbeTool, ParamMinerTool, TakeoverTool
from .nextjs_probe import MiddlewareBypassTool, NextImageProxyTool
from .client_audit import CookieAuditTool, SriAuditTool
from .exploitability import ExploitabilityProbeTool
from .secret_scan import SecretScanTool
from .security_headers import SecurityHeadersTool
from .session_probe import SessionProbeTool
from .sourcemap_probe import SourcemapProbeTool
from .sqli_probe import SqliProbeTool
from .template_probe import TemplateProbeTool
from .tls_audit import TlsAuditTool
from .xss_probe import XssProbeTool

__all__ = [
    "Tool", "ToolContext", "ToolRegistry", "ToolResult", "redact",
    "build_default_registry",
]


def build_default_registry(ctx: ToolContext) -> ToolRegistry:
    reg = ToolRegistry(ctx)
    for tool in (
        HttpProbeTool(),
        SecurityHeadersTool(),
        TlsAuditTool(),
        EmailProbeTool(),
        BrowserEngineTool(),
        CrawlerTool(),
        LivenessProbeTool(),
        CookieAuditTool(),
        SriAuditTool(),
        MiddlewareBypassTool(),
        NextImageProxyTool(),
        MethodAuditTool(),
        DirProbeTool(),
        SqliProbeTool(),
        XssProbeTool(),
        RedirectProbeTool(),
        HeaderPolicyTool(),
        WsProbeTool(),
        WaybackTool(),
        IdSeqTool(),
        CtLogTool(),
        SmuggleTool(),
        CacheDecTool(),
        OAuthTool(),
        PuzzleTool(),
        JsonInjTool(),
        CtaConfTool(),
        VerbOverrideTool(),
        SmtpProbeTool(),
        DkimProbeTool(),
        ApiVerTool(),
        GqlBatchTool(),
        GqlDepthTool(),
        GqlAliasTool(),
        PaginationTool(),
        SortFilterTool(),
        JwtHeaderTool(),
        JwtCrackTool(),
        ProtoClientTool(),
        ProtoServerTool(),
        DomClobberTool(),
        CssInjectionTool(),
        Sourcemap2Tool(),
        MqMgmtTool(),
        DomXssTool(),
        ClickjackTool(),
        BolaTool(),
        PrivMatrixTool(),
        ParamMinerTool(),
        AuthzBypassTool(),
        TakeoverTool(),
        LlmProbeTool(),
        ExploitabilityProbeTool(),
        AuthProbeTool(),
        DeepProbeTool(),
        FuzzEngineTool(),
        SessionProbeTool(),
        TemplateProbeTool(),
        SourcemapProbeTool(),
        LoadProbeTool(),
        CodeAuditTool(),
        ScaProbeTool(),
        SecretScanTool(),
        JsCredSweepTool(),
        WpProbeTool(),
        DebugPageTool(),
    ):
        reg.register(tool)
    return reg
