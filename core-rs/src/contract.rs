//! Kontrak findings.json — SATU PINTU. Harus identik dengan
//! `core/findings.py` (python). Setiap pergeseran = bug kontrak.
//!
//! Verdict ladder: 0 OBSERVED, 1 SUSPECTED, 2 REPRODUCED,
//! 3 DETERMINISTICALLY_VERIFIED, 4 IMPACT_VERIFIED, 5 BLIND_VALIDATED,
//! -1 REJECTED. MIN_REPORT_LEVEL = 3 (di bawah itu = LEAD).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];
pub const MIN_REPORT_LEVEL: i8 = 3;

pub fn verdict_name(level: i8) -> &'static str {
    match level {
        0 => "OBSERVED",
        1 => "SUSPECTED",
        2 => "REPRODUCED",
        3 => "DETERMINISTICALLY_VERIFIED",
        4 => "IMPACT_VERIFIED",
        5 => "BLIND_VALIDATED",
        -1 => "REJECTED",
        _ => "UNKNOWN",
    }
}

/// Identik dengan `verdict_tag()` python: `L{level} {NAME dgn spasi}`
/// plus sufiks " - LEAD" untuk level < MIN_REPORT_LEVEL (termasuk L0),
/// dan "L-x REJECTED" untuk -1.
pub fn verdict_tag(level: i8) -> String {
    if level == -1 {
        return "L-x REJECTED".to_string();
    }
    let name = verdict_name(level).replace('_', " ");
    if level < MIN_REPORT_LEVEL {
        format!("L{level} {name} - LEAD")
    } else {
        format!("L{level} {name}")
    }
}

/// Baris findings.json — field opsional ditoleransi agar skill lama
/// tetap valid; field wajib: tool, title, severity, verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Finding {
    pub tool: String,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub recommendation: String,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub evidence_kind: Option<String>,
    #[serde(default)]
    pub finding_class: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default = "default_status")]
    pub status: String,
    pub verdict: i8,
    pub verdict_tag: String,
    pub id: String,
    #[serde(default)]
    pub reportable: bool,
    #[serde(default)]
    pub lab_only: bool,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub param: Option<String>,
    /// Field tambahan (category, safety_class, dsb.) diteruskan apa adanya
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_confidence() -> f64 {
    0.5
}

fn default_status() -> String {
    "unconfirmed".to_string()
}

impl Finding {
    /// Validasi + normalisasi baris temuan: severity valid, verdict_tag
    /// harus cocok format kontrak, id harus deterministik. Return Err
    /// dengan alasan spesifik (fail-closed, bukan diam-diam lolos).
    pub fn validate(&self) -> Result<(), String> {
        if !SEVERITIES.contains(&self.severity.as_str()) {
            return Err(format!("invalid severity: {}", self.severity));
        }
        if !matches!(
            self.status.as_str(),
            "confirmed" | "unconfirmed" | "false-positive"
        ) {
            return Err(format!("invalid status: {}", self.status));
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(format!(
                "confidence out of range 0.0..1.0: {}",
                self.confidence
            ));
        }
        if let Some(cwe) = &self.cwe {
            if !cwe.is_empty() && !is_valid_cwe(cwe) {
                return Err(format!("invalid cwe format: {cwe}"));
            }
        }
        if self.verdict < -1 || self.verdict > 5 {
            return Err(format!("verdict out of range L-x..L5: {}", self.verdict));
        }
        let expect_tag = verdict_tag(self.verdict);
        if self.verdict_tag != expect_tag {
            return Err(format!(
                "verdict_tag mismatch: got '{}', contract '{}'",
                self.verdict_tag, expect_tag
            ));
        }
        let file_path = self
            .file_path
            .as_deref()
            .or_else(|| self.extra.get("file_path").and_then(|v| v.as_str()));
        let param = self
            .param
            .as_deref()
            .or_else(|| self.extra.get("param").and_then(|v| v.as_str()));
        let expect_id = finding_id(
            &self.tool,
            &self.title,
            self.target_url.as_deref(),
            file_path,
            param,
        );
        if self.id != expect_id {
            return Err(format!(
                "id mismatch: got '{}', contract '{}'",
                self.id, expect_id
            ));
        }
        let expect_reportable = self.verdict >= MIN_REPORT_LEVEL;
        if self.reportable != expect_reportable {
            return Err(format!(
                "reportable mismatch: verdict {} => {expect_reportable}",
                self.verdict
            ));
        }
        Ok(())
    }
}

fn is_valid_cwe(s: &str) -> bool {
    // CWE-XXX atau CWE-XXXX, mis. CWE-79, CWE-614
    if !s.starts_with("CWE-") {
        return false;
    }
    let num = &s[4..];
    !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) && num.len() <= 5
}

/// id = sha256(tool|title|target_url|file_path|param)[:16] — identik
/// python. file_path/param None = string kosong.
pub fn finding_id(
    tool: &str,
    title: &str,
    target_url: Option<&str>,
    file_path: Option<&str>,
    param: Option<&str>,
) -> String {
    let basis = format!(
        "{}|{}|{}|{}|{}",
        tool,
        title,
        target_url.unwrap_or(""),
        file_path.unwrap_or(""),
        param.unwrap_or("")
    );
    let digest = Sha256::digest(basis.as_bytes());
    hex16(&digest)
}

fn hex16(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(16);
    for b in bytes.iter().take(8) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Dokumen findings.json satu pintu.
#[derive(Debug, Serialize, Deserialize)]
pub struct FindingsDoc {
    pub ok: bool,
    #[serde(default)]
    pub data: serde_json::Value,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub requests: u32,
}
