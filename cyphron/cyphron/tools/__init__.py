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
from .wp_data_exposure import WpDataExposureTool
from .lockout_probe import LockoutProbeTool
from .security_txt import SecurityTxtTool
from .cors_probe import CorsProbeTool
from .register_probe import RegisterProbeTool
from .reset_enum import ResetEnumTool
from .traversal_probe import TraversalTool
from .ssrf_oob import SsrfOobTool
from .crlf_probe import CrlfProbeTool
from .admin_panel import AdminPanelTool
from .laravel_panel import LaravelPanelTool
from .actuator import ActuatorTool
from .xmlrpc_probe import XmlRpcProbeTool
from .subdomain_brute import SubdomainBruteTool
from .passive_dns import PassiveDnsTool
from .api_surface_probe import ApiSurfaceProbeTool
from .apk_surface_probe import ApkSurfaceProbeTool
from .error_oracle import ErrorOracleTool
from .github_osint import GithubOsintTool
from .header_ws_engines import HeaderPolicyTool, WsProbeTool
from .recon_oauth_engines import (
    CacheDecTool,
    CtLogTool,
    IdSeqTool,
    JsonInjTool,
    OAuthTool,
    PuzzleTool,
    SmuggleTool,
    WaybackTool,
)
from .api_email_engines import (
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
from .crypto_web_engines import (
    CssInjectionTool,
    DomClobberTool,
    JwtCrackTool,
    JwtHeaderTool,
    ProtoClientTool,
    ProtoServerTool,
)
from .infra_xss_engines import (
    ClickjackTool,
    DomXssTool,
    MqMgmtTool,
    Sourcemap2Tool,
)
from .authz_engines import BolaTool, PrivMatrixTool
from .bounty_engines import AuthzBypassTool, LlmProbeTool, ParamMinerTool, TakeoverTool
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
        WpDataExposureTool(),
        LockoutProbeTool(),
        SecurityTxtTool(),
        CorsProbeTool(),
        RegisterProbeTool(),
        ResetEnumTool(),
        TraversalTool(),
        SsrfOobTool(),
        CrlfProbeTool(),
        AdminPanelTool(),
        LaravelPanelTool(),
        ActuatorTool(),
        DebugPageTool(),
        XmlRpcProbeTool(),
        SubdomainBruteTool(),
        PassiveDnsTool(),
        ApiSurfaceProbeTool(),
        ApkSurfaceProbeTool(),
        ErrorOracleTool(),
        GithubOsintTool(),
    ):
        reg.register(tool)
    return reg
