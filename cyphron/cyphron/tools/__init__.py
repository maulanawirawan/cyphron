"""Default tool registry — Cyphron's built-in engines (own code only)."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolRegistry, ToolResult, redact
from .auth_probe import AuthProbeTool
from .browser_engine import BrowserEngineTool
from .browser_scout import BrowserScoutTool
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
from .sqli_extract import SqliExtractTool
from .ssti_rce import SstiRceTool
from .lfi_read import LfiReadTool
from .auth_bypass_matrix import AuthBypassMatrixTool
from .proto_pollution import ProtoPollutionTool
from .xxe_probe import XxeProbeTool
from .nosqli_probe import NosqliProbeTool
from .host_header_poison import HostHeaderPoisonTool
from .jndi_probe import JndiProbeTool
from .jwt_exploit import JwtExploitTool
from .ssrf_chain import SsrfChainTool
from .rce_proof import RceProofTool
from .deser_probe import DeserProbeTool
from .cache_poison import CachePoisonTool
from .gql_schema_engines import GqlIntrospectTool, GraphqlFieldSuggestTool
from .mass_assign import MassAssignTool
from .cloud_bucket_probe import CloudBucketProbeTool
from .oauth_state_bypass import OAuthStateBypassTool
from .idor_mass_endpoint import IdorMassEndpointTool
from .csp_analyzer import CspAnalyzerTool
from .cookie_scope import CookieScopeTool
from .cors_wildcard_subdomain import CorsSubdomainReflectionTool
from .tls_mismatch_leak import CtSanLeakTool
from .api_version_diff import ApiVersionDiffTool
from .header_reflection import HeaderReflectionTool
from .email_pattern import EmailPatternTool
from .rate_limit_graceful import RateLimitGracefulTool
from .archive_diff import ArchiveDiffTool
from .security_txt_quality import SecurityTxtQualityTool
from .cookie_prefix_insecure import CookiePrefixInsecureTool
from .referrer_policy_loose import ReferrerPolicyLooseTool
from .cache_control_missing import CacheControlMissingTool
from .sri_subresource import SriSubresourceTool
from .hsts_short_maxage import HstsShortMaxageTool
from .robots_sensitive_entry import RobotsSensitiveEntryTool
from .server_banner_soft import ServerBannerSoftTool
from .favicon_hash import FaviconHashTool
from .fingerprint_to_cpe import FingerprintToCpeTool
from .cve_matcher import CveMatcherTool
from .edb_reference import EdbReferenceTool
from .nuclei_bridge import NucleiBridgeTool
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
from .identity_matrix import IdentityMatrixTool
from .business_logic import BusinessLogicTool
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
        BrowserScoutTool(),
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
        IdentityMatrixTool(),
        BusinessLogicTool(),
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
        SqliExtractTool(),
        SstiRceTool(),
        LfiReadTool(),
        AuthBypassMatrixTool(),
        ProtoPollutionTool(),
        XxeProbeTool(),
        NosqliProbeTool(),
        HostHeaderPoisonTool(),
        JndiProbeTool(),
        JwtExploitTool(),
        SsrfChainTool(),
        RceProofTool(),
        DeserProbeTool(),
        CachePoisonTool(),
        GqlIntrospectTool(),
        GraphqlFieldSuggestTool(),
        MassAssignTool(),
        CloudBucketProbeTool(),
        OAuthStateBypassTool(),
        IdorMassEndpointTool(),
        CspAnalyzerTool(),
        CookieScopeTool(),
        CorsSubdomainReflectionTool(),
        CtSanLeakTool(),
        ApiVersionDiffTool(),
        HeaderReflectionTool(),
        EmailPatternTool(),
        RateLimitGracefulTool(),
        ArchiveDiffTool(),
        SecurityTxtQualityTool(),
        CookiePrefixInsecureTool(),
        ReferrerPolicyLooseTool(),
        CacheControlMissingTool(),
        SriSubresourceTool(),
        HstsShortMaxageTool(),
        RobotsSensitiveEntryTool(),
        ServerBannerSoftTool(),
        FaviconHashTool(),
        FingerprintToCpeTool(),
        CveMatcherTool(),
        EdbReferenceTool(),
        NucleiBridgeTool(),
    ):
        reg.register(tool)
    # Fullpower B1: engine polyglot via manifest adapter (satu pintu guardrail)
    from ..adapter import AdapterEngine, load_manifests
    _adapters, _adapter_errors = load_manifests()
    for _mf in _adapters:
        try:
            reg.register(AdapterEngine(_mf))
        except Exception:
            continue
    return reg
