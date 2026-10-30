//! F6 — Orchestrator native: satu perintah `cyphron scan` menjalankan
//! pipa recon -> findings.json (satu pintu) -> laporan PDF.
//!
//! Dibangun dari nol di core (Rust) — pengganti langsung pipa
//! orchestrator + worker + queue di platform sejenis, tanpa infra
//! tambahan: binary yang sama, kontrak yang sama.
//!
//! Gerbang safety (fail-closed):
//!   mode tier0 : hanya skill read-only + 1-request (data publik)
//!   mode lab   : apa pun di registry (wajib --lab, LAB=1 gagal-closed
//!                tetap jadi tanggung jawab skill masing-masing)
//! Skill dengan safety class lain (active-probe, credential-bearing,
//! state-changing) TIDAK ADA di registry tier0 dan TIDAK boleh masuk
//! tanpa kelas + otorisasi eksplisit — registry adalah allowlist.

use crate::contract::Finding;
use crate::fao;
use crate::runner::{run_skill_with_env, write_merged};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Registry schema — hardened, fail-closed
// ---------------------------------------------------------------------------

/// Daftar kelas yang diizinkan — enum tertutup. Nilai di luar ini = fail-closed.
pub const KNOWN_SAFETY_CLASSES: &[&str] = &[
    "read-only",
    "1-request",
    "bounded-requests",
    "active-probe",
    "credential-bearing",
    "state-changing",
];

/// Kelas yang HANYA boleh jalan di mode lab. Di tier0 di-skip dengan baris audit.
pub const LAB_ONLY_CLASSES: &[&str] = &[
    "active-probe",
    "credential-bearing",
    "state-changing",
];

/// Budget-request default per run (hard cap). Registry 45+ skill per
/// target bisa meledakkan jumlah request — tanpa cap, satu skill yang
/// "bohong" (bounded-requests tanpa batas nyata) bisa mengirim ratusan.
pub const DEFAULT_MAX_REQUESTS: usize = 64;

/// Estimasi MAKSIMAL request per skill berdasar safety class — dipakai
/// untuk proyeksi budget SEBELUM skill dijalankan. Skill yang membocorkan
/// lebih dari estimasi ini tetap dihitung aktualnya (audit, bukan diam).
pub fn estimate_max_requests(safety_class: &str) -> usize {
    match safety_class {
        "read-only" => 0,
        "1-request" => 1,
        "bounded-requests" => 5,
        // kelas lab (active-probe dkk.) tidak pernah jalan di tier0;
        // di lab, budget dihitung aktual — estimasi tidak membatasi.
        _ => usize::MAX,
    }
}

fn is_known_safety_class(s: &str) -> bool {
    KNOWN_SAFETY_CLASSES.contains(&s)
}

fn is_lab_only_class(s: &str) -> bool {
    LAB_ONLY_CLASSES.contains(&s)
}

#[derive(Debug, Deserialize)]
pub struct SkillSpec {
    pub name: String,
    pub cmd: Vec<String>,
    pub safety_class: String,
    pub needs: String,
    #[serde(default)]
    pub requires_evidence: bool,
    /// Flag eksplisit lab_only (opsional, default false). Jika true, skill
    /// hanya boleh jalan di mode lab — fail-closed tier0.
    #[serde(default)]
    pub lab_only: bool,
}

#[derive(Debug, Deserialize)]
pub struct Registry {
    pub version: u32,
    pub skills: Vec<SkillSpec>,
}

/// Validasi skema registry secara ketat (fail-closed).
/// Dipanggil segera setelah deserialize — menolak registry cacat sebelum skill apa pun jalan.
pub fn validate_registry(reg: &Registry) -> Result<(), String> {
    // version harus integer >0 (u32 sudah integer, cek >0)
    if reg.version == 0 {
        return Err("registry.version must be integer >0 — fail-closed".into());
    }
    if reg.skills.is_empty() {
        return Err("registry.skills must be non-empty array — fail-closed".into());
    }
    let mut seen_names: HashSet<String> = HashSet::new();
    for s in &reg.skills {
        // name unik & non-empty
        if s.name.trim().is_empty() {
            return Err("registry skill.name must be non-empty — fail-closed".into());
        }
        if !seen_names.insert(s.name.clone()) {
            return Err(format!(
                "registry skill.name '{}' duplicate — fail-closed (name must be unique)",
                s.name
            ));
        }
        // cmd non-empty vec with at least 2 elements (program + args or program + -c)
        if s.cmd.is_empty() {
            return Err(format!(
                "registry skill '{}': cmd must be non-empty array — fail-closed",
                s.name
            ));
        }
        if s.cmd.len() < 2 {
            return Err(format!(
                "registry skill '{}': cmd must have at least 2 elements (program + args) — fail-closed",
                s.name
            ));
        }
        for (i, c) in s.cmd.iter().enumerate() {
            if c.trim().is_empty() {
                return Err(format!(
                    "registry skill '{}': cmd[{}] must be non-empty — fail-closed",
                    s.name, i
                ));
            }
        }
        // safety_class enum tertutup
        if !is_known_safety_class(&s.safety_class) {
            return Err(format!(
                "registry skill '{}': unknown safety_class '{}' — fail-closed (allowed: {})",
                s.name,
                s.safety_class,
                KNOWN_SAFETY_CLASSES.join(", ")
            ));
        }
        // needs enum (longgar tapi validasi nilai umum)
        match s.needs.as_str() {
            "none" | "domain" | "target" | "source" => {},
            other => {
                return Err(format!(
                    "registry skill '{}': unknown needs '{}' (allowed: none|domain|target|source) — fail-closed",
                    s.name, other
                ));
            }
        }
        // lab_only sudah bool via serde default — tidak perlu validasi tambahan
    }
    Ok(())
}

pub fn load_registry(path: &Path) -> Result<Registry, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("registry {path:?}: {e}"))?;
    let reg: Registry =
        serde_json::from_str(&raw).map_err(|e| format!("registry invalid: {e}"))?;
    validate_registry(&reg).map_err(|e| format!("registry {path:?} schema violation: {e}"))?;
    Ok(reg)
}

/// Skill yang BOLEH jalan pada mode tertentu. tier0 = data publik murni.
pub fn allowed_safety_classes(mode: &str) -> Result<Vec<&'static str>, String> {
    match mode {
        "tier0" => Ok(vec!["read-only", "1-request", "bounded-requests"]),
        "lab" => Ok(vec!["read-only", "1-request", "bounded-requests",
                         "active-probe", "credential-bearing",
                         "state-changing"]),
        other => Err(format!(
            "mode '{other}' tidak dikenal (tier0 | lab) — fail-closed"
        )),
    }
}

pub struct ScanParams {
    pub mode: String,
    pub target: Option<String>,
    pub domain: Option<String>,
    pub evidence: Option<String>,
    /// F70 — path sumber LOKAL untuk skill review kode/konfigurasi
    /// (repo-secret-scan, infra-config-audit): 0 request jaringan.
    pub source: Option<String>,
    pub out_dir: PathBuf,
    pub registry: PathBuf,
    pub report: bool,
    pub dry_run: bool,
    /// Hard cap request ke target per run. 0 = fail-closed (ditolak).
    pub max_requests: usize,
    /// F20 — profil User-Agent: None = identitas alat (default jujur);
    /// Some("browser") = UA Chrome realistis; Some(custom) = string bebas.
    pub ua: Option<String>,
    /// F20 — proxy untuk SELURUH request run (termasuk DoH): env
    /// HTTP_PROXY/HTTPS_PROXY/ALL_PROXY untuk proses skill.
    pub proxy: Option<String>,
    /// F20b — file daftar proxy (satu URL per baris, # = komentar):
    /// round-robin deterministik per skill. Tidak boleh digabung
    /// dengan --proxy. Semua penugasan tercatat di data.sources.
    pub proxies_file: Option<String>,
}

/// Muat pool proxy dari file — satu URL per baris, kosong/# di-skip.
/// Fail-closed: file tidak ada / tidak ada proxy valid / skema tidak
/// dikenal = error. Userinfo (kredensial) dipisahkan dari tampilan.
pub fn load_proxy_pool(path: &str) -> Result<Vec<String>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("proxies-file {path:?}: {e}"))?;
    let mut pool = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let valid = line.starts_with("http://") || line.starts_with("https://")
            || line.starts_with("socks5://");
        if !valid {
            return Err(format!(
                "proxies-file {path:?}: baris tidak valid '{line}' — harus http:// https:// atau socks5:// — fail-closed"
            ));
        }
        if !pool.contains(&line.to_string()) {
            pool.push(line.to_string());
        }
    }
    if pool.is_empty() {
        return Err(format!(
            "proxies-file {path:?}: kosong — tidak ada proxy valid — fail-closed"
        ));
    }
    Ok(pool)
}

/// Redaksi kredensial dari URL proxy untuk audit: http://user:pass@host:port
/// -> http://***@host:port (rincian tetap operasional di file sumber).
pub fn redact_proxy(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_, host)) => format!("{scheme}://***@{host}"),
            None => url.to_string(),
        },
        None => "***".into(),
    }
}

/// Env untuk SATU skill: gabungan low_profile global + proxy rotasi
/// skill tsb (menimpa env global bila ada).
pub fn skill_env(p: &ScanParams, proxy: Option<&str>) -> Vec<(String, String)> {
    let mut env = low_profile_env(p);
    if let Some(px) = proxy {
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            env.retain(|(k, _)| k != key);
            env.push((key.to_string(), px.to_string()));
        }
    }
    env
}

/// Env yang diinjeksikan ke setiap proses skill untuk run ini.
pub fn low_profile_env(p: &ScanParams) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    if let Some(ua) = &p.ua {
        if !ua.trim().is_empty() {
            env.push(("CYPHRON_UA".into(), ua.trim().into()));
        }
    }
    if let Some(proxy) = &p.proxy {
        if !proxy.trim().is_empty() {
            let proxy = proxy.trim().to_string();
            env.push(("HTTP_PROXY".into(), proxy.clone()));
            env.push(("HTTPS_PROXY".into(), proxy.clone()));
            env.push(("ALL_PROXY".into(), proxy));
        }
    }
    env
}

#[derive(Debug)]
pub struct ScanResult {
    pub skills_run: Vec<String>,
    /// Skill yang dilewati karena budget-request habis (baris audit).
    pub skipped_budget: Vec<String>,
    pub total_findings: usize,
    pub reportable: usize,
    pub requests: usize,
    pub merged_path: PathBuf,
    pub pdf_path: Option<PathBuf>,
    pub elapsed_s: f64,
}

/// Seleksi skill (publik — dipakai run_scan DAN cmd_queue): kelas
/// diizinkan + kebutuhan variabel tersedia + aturan mode bukti + gating lab_only.
pub fn select_skills<'a>(reg: &'a Registry, p: &ScanParams,
                         allowed: &[&'static str]) -> Vec<&'a SkillSpec> {
    let mut selected: Vec<&SkillSpec> = Vec::new();
    for s in &reg.skills {
        // Enforce lab_only: skip lab-only classes in tier0 with audit
        if LAB_ONLY_CLASSES.contains(&s.safety_class.as_str()) && p.mode != "lab" {
            eprintln!("skip lab-only skill {} in tier0 (audit)", s.name);
            continue;
        }
        if s.lab_only && p.mode != "lab" {
            eprintln!("skip lab-only skill {} in tier0 (audit)", s.name);
            continue;
        }
        // 1) Gate allowlist mode
        if !allowed.contains(&s.safety_class.as_str()) {
            // Audit line untuk kelas high-risk yang ditolak di tier0
            if is_lab_only_class(&s.safety_class) || s.lab_only {
                eprintln!("skip lab-only skill {} in tier0 (audit)", s.name);
            }
            continue;
        }
        if s.requires_evidence && p.evidence.is_none() {
            continue;
        }
        if p.evidence.is_some() && s.safety_class == "1-request" {
            continue; // kebijakan nol-request saat mode bukti
        }
        match s.needs.as_str() {
            "none" => selected.push(s),
            "domain" if p.domain.is_some() => selected.push(s),
            "target" if p.target.is_some() => selected.push(s),
            "source" if p.source.is_some() => selected.push(s),
            _ => {}
        }
    }
    selected
}

// ---------------------------------------------------------------------------
// Python executable resolution — sys.executable fallback chain
// ---------------------------------------------------------------------------

/// Helper find_python — coba env var PYTHON, lalu "python", "python3", "py".
/// Probe via Command::new(candidate).arg("--version").status(), pick first yang exit 0, else fail.
pub fn find_python() -> Result<String, String> {
    if let Ok(env_py) = std::env::var("PYTHON") {
        if !env_py.trim().is_empty() {
            let ok = std::process::Command::new(&env_py)
                .arg("--version")
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                return Ok(env_py);
            }
        }
    }
    for cand in ["python", "python3", "py"] {
        let ok = std::process::Command::new(cand)
            .arg("--version")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Ok(cand.to_string());
        }
    }
    Err("no python interpreter found (tried PYTHON env, python, python3, py) — fail-closed".into())
}

/// Cari python executable yang tersedia: coba PYTHON env, lalu python3, lalu python.
/// Mengembalikan nama executable yang lulus `--version`. Fail-closed: jika tidak ada
/// yang ditemukan, kembalikan "python" dan biarkan caller error dengan pesan jelas.
pub fn resolve_python() -> String {
    find_python().unwrap_or_else(|_| "python".to_string())
}

pub fn run_scan(p: &ScanParams) -> Result<ScanResult, String> {
    // fail-closed: budget 0 tidak berarti "tanpa batas" — itu penyalahgunaan
    // F20b — pool proxy rotasi (opsional). Konflik dengan --proxy =
    // fail-closed (pilih satu mode egress, jangan campur). Dimuat di
    // awal: fail-closed ikut berlaku pada --dry-run.
    if p.proxy.is_some() && p.proxies_file.is_some() {
        return Err("--proxy dan --proxies tidak boleh digabung — pilih "
            .to_string() + "satu mode egress — fail-closed");
    }
    let proxy_pool: Vec<String> = match &p.proxies_file {
        Some(path) => load_proxy_pool(path)?,
        None => Vec::new(),
    };
    if p.max_requests == 0 {
        return Err("max_requests=0 tidak valid (0 bukan 'tanpa batas') — "
            .to_string() + "fail-closed");
    }
    let allowed = allowed_safety_classes(&p.mode)?;
    let reg = load_registry(&p.registry)?;
    let selected = select_skills(&reg, p, &allowed);

    // --dry-run: print selected skills table: name | safety_class | needs and return Ok with 0 findings without executing. Must still validate registry and allowed classes (already done above).
    if p.dry_run {
        println!("dry-run mode={} allowed=[{}]", p.mode, allowed.join(", "));
        println!(
            "low-profile: ua={} egress={}",
            p.ua.as_deref().unwrap_or("default"),
            if p.proxy.is_some() {
                "satu proxy".to_string()
            } else if !proxy_pool.is_empty() {
                format!("round-robin {} proxy", proxy_pool.len())
            } else {
                "langsung".to_string()
            }
        );
        println!("registry: {} version={} total_skills={}", p.registry.display(), reg.version, reg.skills.len());
        println!("selected {} skill(s):", selected.len());
        println!("name | safety_class | needs | max_requests_est");
        for s in &selected {
            println!("{} | {} | {} | {}", s.name, s.safety_class, s.needs,
                     estimate_max_requests(&s.safety_class));
        }
        if selected.is_empty() {
            println!("(no skills selected — fail-closed would trigger on real run)");
        } else {
            println!("dry-run: no skills executed, no requests sent, no files written");
        }
        return Ok(ScanResult {
            skills_run: selected.iter().map(|s| s.name.clone()).collect(),
            skipped_budget: Vec::new(),
            total_findings: 0,
            reportable: 0,
            requests: 0,
            merged_path: p.out_dir.join("findings.json"),
            pdf_path: None,
            elapsed_s: 0.0,
        });
    }

    if selected.is_empty() {
        return Err("tidak ada skill yang cocok untuk mode/target ini — fail-closed".into());
    }

    let out_dir = &p.out_dir;
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut skills_run = Vec::new();
    let mut skipped_budget: Vec<String> = Vec::new();
    let mut requests = 0usize;
    let mut per_skill_sources: Vec<serde_json::Value> = Vec::new();
    let t0 = Instant::now();

    for (skill_idx, s) in selected.iter().enumerate() {
        // --- Budget-request per run (hard cap): proyeksi dari safety
        // class SEBELUM skill dijalankan; skill yang melebihi sisa budget
        // di-skip dengan baris audit (bukan diam-diam).
        // Enforce hanya di tier0: lab sudah lewat gerbang otorisasi dan
        // kelas lab punya estimasi tak terbatas — di lab budget hanya
        // metadata + baris audit (actual tetap dihitung).
        if p.mode == "tier0" {
            let est = estimate_max_requests(&s.safety_class);
            let remaining = p.max_requests.saturating_sub(requests);
            if est > remaining {
                eprintln!(
                    "skip {}: budget-request habis (est {} > sisa {}) (audit)",
                    s.name, est, remaining
                );
                skipped_budget.push(s.name.clone());
                continue;
            }
        }

        // F20b — egress rotasi: satu skill = satu proxy (round-robin
        // deterministik); penugasan tercatat di data.sources.
        let skill_proxy: Option<&String> = if proxy_pool.is_empty() {
            None
        } else {
            Some(&proxy_pool[skill_idx % proxy_pool.len()])
        };

        let out_path = out_dir.join(format!("{}.json", s.name));
        let argv: Vec<String> = s
            .cmd
            .iter()
            .map(|a| {
                a.replace("@TARGET@", p.target.as_deref().unwrap_or(""))
                    .replace("@DOMAIN@", p.domain.as_deref().unwrap_or(""))
                    .replace("@EVIDENCE@", p.evidence.as_deref().unwrap_or(""))
                    .replace("@SOURCE@", p.source.as_deref().unwrap_or(""))
                    .replace("@OUT@", &out_path.to_string_lossy().to_string())
            })
            .collect();
        let res = run_skill_with_env(
            &argv,
            &out_path,
            None,
            &skill_env(p, skill_proxy.map(|x| x.as_str())),
        )?;
        if !res.ok {
            return Err(format!(
                "skill '{}' melanggar kontrak ({}) — scan dihentikan (fail-closed)",
                s.name,
                res.invalid.join("; ")
            ));
        }
        skills_run.push(s.name.clone());

        // Gabungkan findings (satu pintu); jumlah request ke target
        // diambil dari meta kontrak masing-masing skill. Kontrak
        // write_findings menulis angka YANG SAMA di top-level dan
        // data.requests — hitung SEKALI (top-level otoritatif, data
        // hanya fallback) supaya budget & density tidak dobel.
        let raw = std::fs::read_to_string(&out_path).map_err(|e| e.to_string())?;
        let doc: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let top_requests = doc
            .get("requests")
            .and_then(|r| r.as_u64());
        let data_requests = doc
            .get("data")
            .and_then(|d| d.get("requests"))
            .and_then(|r| r.as_u64())
            .unwrap_or(0) as usize;
        let skill_requests = match top_requests {
            Some(n) => n as usize,
            None => data_requests,
        };
        requests = requests.saturating_add(skill_requests);
        // Hard-fail (audit 2026-10): dulu overflow hanya dicatat lalu scan
        // lanjut — "hard cap" di dokumentasi tidak sesuai perilaku. Sekarang
        // pelanggaran budget = pelanggaran kontrak: run berhenti fail-closed.
        // (Penegakan di lapisan jaringan untuk proses eksternal = roadmap
        // native-engine; ini gerbang akuntansi yang tegas.)
        if requests > p.max_requests {
            return Err(format!(
                "budget-request terlampaui oleh '{}': {} > {} — scan dihentikan (fail-closed)",
                s.name, requests, p.max_requests
            ));
        }
        // Skill yang TIDAK melacak request-nya sendiri tidak bisa ditagih
        // budget-nya — di tier0 itu lubang kebocoran: ditolak, bukan
        // diasumsikan nol. (nuclei_runner dll = kelas lab, bukan tier0.)
        if p.mode == "tier0" {
            let untracked = doc
                .get("data")
                .and_then(|d| d.get("requests_untracked"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                || doc.get("requests_untracked").and_then(|v| v.as_bool()).unwrap_or(false);
            if untracked {
                return Err(format!(
                    "skill '{}' tidak melacak jumlah request-nya (requests_untracked) — tier0 menolak budget yang tak bisa ditegakkan (fail-closed)",
                    s.name
                ));
            }
        }
        per_skill_sources.push(serde_json::json!({
            "skill": s.name,
            "safety_class": s.safety_class,
            "requests": skill_requests,
            "proxy": skill_proxy.map(|px| redact_proxy(px)),
        }));
        if let Some(arr) = doc.get("findings").and_then(|f| f.as_array()) {
            for f in arr {
                let parsed: Finding = serde_json::from_value(f.clone())
                    .map_err(|e| format!("baris invalid: {e}"))?;
                parsed.validate()?;
                all_findings.push(parsed);
            }
        }
    }

    // fail-closed: budget menghabiskan SEMUA skill = run gagal, bukan
    // sukses kosong (hasil kosong yang "sukses" menyesatkan triage).
    if skills_run.is_empty() {
        return Err(format!(
            "budget-request ({}): semua skill di-skip, tidak ada yang jalan — fail-closed",
            p.max_requests
        ));
    }

    let merged_path = out_dir.join("findings.json");
    // FAO: dedup + quorum + cross-confirm + evidence hash (F8)
    fao::correlate(&mut all_findings);
    // Hardened merged writer: include per-skill requests in data.sources + total requests
    // (runner::write_merged dipakai untuk kompatibilitas, tapi kita enrich di sini)
    // Tulis dengan per_skill_sources agar audit jelas berapa request per skill.
    {
        // Prefer enriched write; fallback ke runner helper jika perlu
        // Kita tulis langsung agar data.sources = per-skill objects
        let doc = serde_json::json!({
            "ok": true,
            "data": {
                "run": "cyphron-core",
                "sources": per_skill_sources,
                "total_findings": all_findings.len(),
                "mode": p.mode,
                "elapsed_s": t0.elapsed().as_secs_f64(),
                "budget": {
                    "max_requests": p.max_requests,
                    "skipped": skipped_budget,
                },
                "low_profile": {
                    "ua": p.ua.clone().unwrap_or_else(|| "default".into()),
                    "proxy": p.proxy.is_some(),
                    "proxies_file": p.proxies_file.clone(),
                    "proxy_count": proxy_pool.len(),
                    "strategy": if proxy_pool.is_empty() { "single" } else { "round-robin-per-skill" },
                },
            },
            "findings": all_findings,
            "requests": requests,
        });
        if let Some(parent) = merged_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(
            &merged_path,
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        // Keep write_merged file for legacy readers? Not needed — merged_path sudah enriched.
        // Untuk menjaga kompatibilitas, pastikan juga runner helper tidak menimpa:
        let _ = write_merged; // suppress unused warning jika future use
    }
    // (opsional) laporan PDF via generator Typst — python via fallback chain
    // Audit 2026-10: PDF dibuat SEBELUM manifest supaya report.pdf ikut
    // tercakup rantai bukti run (dulu manifest ditulis lebih dulu — PDF
    // terbaru tidak terdaftar).
    let mut pdf_path = None;
    if p.report {
        let out_pdf = out_dir.join("report.pdf");
        let py = resolve_python();
        let status = std::process::Command::new(&py)
            .arg("tools/report_pdf.py")
            .arg("--findings")
            .arg(&merged_path)
            .arg("--out")
            .arg(&out_pdf)
            .status()
            .map_err(|e| format!("report generator ({}): {e}", py))?;
        if status.success() {
            pdf_path = Some(out_pdf);
        } else {
            return Err(format!("generator laporan gagal ({} exit {:?}) — fail-closed", py, status.code()));
        }
    }

    // run-manifest: sha256 semua artefak run (rantai bukti tingkat run)
    let mut manifest_files: Vec<PathBuf> = vec![merged_path.clone()];
    if let Some(pdf) = &pdf_path {
        manifest_files.push(pdf.clone());
    }
    manifest_files.extend(out_dir.read_dir().into_iter().flatten().flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false)
            && p.file_name().map(|n| n != "run-manifest.json").unwrap_or(true)));
    fao::write_run_manifest(out_dir, &manifest_files)?;

    let reportable = all_findings.iter().filter(|f| f.reportable).count();
    Ok(ScanResult {
        skills_run,
        skipped_budget,
        total_findings: all_findings.len(),
        reportable,
        requests,
        merged_path,
        pdf_path,
        elapsed_s: t0.elapsed().as_secs_f64(),
    })
}

/// CLI scan (blocking) — dipanggil dari main.
pub fn cmd_scan(args: &[String]) -> i32 {
    let mut p = ScanParams {
        mode: "tier0".into(),
        target: None,
        domain: None,
        evidence: None,
        source: None,
        out_dir: PathBuf::from("findings/scan"),
        registry: PathBuf::from("skills/registry.json"),
        report: false,
        dry_run: false,
        max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => { p.mode = args.get(i+1).cloned().unwrap_or(p.mode); i += 2; }
            "--target" => { p.target = args.get(i+1).cloned(); i += 2; }
            "--domain" => { p.domain = args.get(i+1).cloned(); i += 2; }
            "--evidence" => { p.evidence = args.get(i+1).cloned(); i += 2; }
            // F70 — review sumber lokal (needs=source); tanpa target
            "--source" => { p.source = args.get(i+1).cloned(); i += 2; }
            "--out" => { p.out_dir = PathBuf::from(args.get(i+1).map(String::as_str).unwrap_or("findings/scan")); i += 2; }
            "--registry" => { p.registry = PathBuf::from(args.get(i+1).map(String::as_str).unwrap_or("skills/registry.json")); i += 2; }
            "--report" => { p.report = true; i += 1; }
            "--lab" => { p.mode = "lab".into(); i += 1; }
            "--dry-run" => { p.dry_run = true; i += 1; }
            "--ua" => {
                let v = args.get(i+1).cloned().unwrap_or_default();
                if v.trim().is_empty() {
                    eprintln!("--ua butuh 'browser' atau string custom — fail-closed");
                    return 2;
                }
                p.ua = Some(v);
                i += 2;
            }
            "--proxies" => {
                let v = args.get(i+1).cloned().unwrap_or_default();
                if v.trim().is_empty() {
                    eprintln!("--proxies butuh path file daftar proxy — fail-closed");
                    return 2;
                }
                p.proxies_file = Some(v);
                i += 2;
            }
            "--proxy" => {
                let v = args.get(i+1).cloned().unwrap_or_default();
                if !(v.starts_with("http://") || v.starts_with("https://")
                    || v.starts_with("socks5://")) {
                    eprintln!("--proxy butuh URL http:// https:// atau socks5:// — fail-closed");
                    return 2;
                }
                p.proxy = Some(v);
                i += 2;
            }
            "--max-requests" => {
                match args.get(i+1).and_then(|v| v.parse::<usize>().ok()) {
                    Some(n) => { p.max_requests = n; i += 2; }
                    None => {
                        eprintln!("--max-requests butuh integer >= 1 — fail-closed");
                        return 2;
                    }
                }
            }
            other => { eprintln!("unknown flag: {other}"); return 2; }
        }
    }
    match run_scan(&p) {
        Ok(r) => {
            if p.dry_run {
                // dry-run already printed details; summary line
                println!(
                    "dry-run OK: {} skill would run, {} allowed classes",
                    r.skills_run.len(),
                    allowed_safety_classes(&p.mode).map(|v| v.join(",")).unwrap_or_default()
                );
            } else {
                println!(
                    "scan OK: {} skill ({} skip budget), {} temuan ({} reportable), {} request (cap {}), {:.1}s -> {}{}",
                    r.skills_run.len(), r.skipped_budget.len(),
                    r.total_findings, r.reportable, r.requests,
                    p.max_requests, r.elapsed_s, r.merged_path.display(),
                    r.pdf_path.as_ref()
                        .map(|p| format!(" + {}", p.display()))
                        .unwrap_or_default()
                );
            }
            0
        }
        Err(e) => {
            eprintln!("SCAN DIHENTIKAN: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier0_mode_rejects_active_probe() {
        let allowed = allowed_safety_classes("tier0").unwrap();
        assert!(!allowed.contains(&"active-probe"));
        assert!(!allowed.contains(&"credential-bearing"));
        assert!(allowed.contains(&"read-only"));
        assert!(allowed.contains(&"1-request"));
    }

    #[test]
    fn unknown_mode_fails_closed() {
        assert!(allowed_safety_classes("aggressive").is_err());
    }

    #[test]
    fn registry_rejects_unknown_safety_class() {
        let reg = Registry {
            version: 1,
            skills: vec![SkillSpec {
                name: "bad".into(),
                cmd: vec!["python".into(), "x.py".into()],
                safety_class: "yolo-probe".into(),
                needs: "none".into(),
                requires_evidence: false,
                lab_only: false,
            }],
        };
        let err = validate_registry(&reg).unwrap_err();
        assert!(err.contains("unknown safety_class"), "got: {err}");
    }

    #[test]
    fn registry_rejects_duplicate_name() {
        let reg = Registry {
            version: 1,
            skills: vec![
                SkillSpec { name: "dup".into(), cmd: vec!["python".into()], safety_class: "read-only".into(), needs: "none".into(), requires_evidence: false, lab_only: false },
                SkillSpec { name: "dup".into(), cmd: vec!["python".into()], safety_class: "read-only".into(), needs: "none".into(), requires_evidence: false, lab_only: false },
            ],
        };
        assert!(validate_registry(&reg).is_err());
    }

    #[test]
    fn registry_rejects_empty_cmd() {
        let reg = Registry {
            version: 1,
            skills: vec![SkillSpec {
                name: "empty".into(),
                cmd: vec![],
                safety_class: "read-only".into(),
                needs: "none".into(),
                requires_evidence: false,
                lab_only: false,
            }],
        };
        assert!(validate_registry(&reg).is_err());
    }

    #[test]
    fn registry_rejects_version_zero() {
        let reg = Registry {
            version: 0,
            skills: vec![SkillSpec {
                name: "ok".into(),
                cmd: vec!["python".into()],
                safety_class: "read-only".into(),
                needs: "none".into(),
                requires_evidence: false,
                lab_only: false,
            }],
        };
        assert!(validate_registry(&reg).is_err());
    }

    #[test]
    fn lab_only_class_skipped_in_tier0_with_audit() {
        let reg = Registry {
            version: 1,
            skills: vec![
                SkillSpec { name: "safe".into(), cmd: vec!["python".into()], safety_class: "read-only".into(), needs: "none".into(), requires_evidence: false, lab_only: false },
                SkillSpec { name: "probe".into(), cmd: vec!["python".into()], safety_class: "active-probe".into(), needs: "none".into(), requires_evidence: false, lab_only: false },
                SkillSpec { name: "creds".into(), cmd: vec!["python".into()], safety_class: "credential-bearing".into(), needs: "none".into(), requires_evidence: false, lab_only: false },
            ],
        };
        let p = ScanParams { mode: "tier0".into(), target: None, domain: None, evidence: None, source: None, out_dir: PathBuf::from("x"), registry: PathBuf::from("x"), report: false, dry_run: false, max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None };
        let allowed = allowed_safety_classes(&p.mode).unwrap();
        let sel = select_skills(&reg, &p, &allowed);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].name, "safe");
        let p_lab = ScanParams { mode: "lab".into(), target: None, domain: None, evidence: None, source: None, out_dir: PathBuf::from("x"), registry: PathBuf::from("x"), report: false, dry_run: false, max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None };
        let allowed_lab = allowed_safety_classes(&p_lab.mode).unwrap();
        let sel_lab = select_skills(&reg, &p_lab, &allowed_lab);
        assert_eq!(sel_lab.len(), 3);
    }

    #[test]
    fn scan_end_to_end_with_fake_registry() {
        // registry sementara dengan dua "skill" python inline yang
        // menulis findings.json valid — tidak menyentuh jaringan
        let tmp = std::env::temp_dir().join(format!("cyphron_scan_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        let script = r#"import json,sys,hashlib
def vid(title,target,verdict,tag):
    h=hashlib.sha256(f"t|{title}|{target}||".encode()).hexdigest()[:16]
    return {"tool":"t","title":title,"severity":"info","description":"d",
            "target_url":target,"evidence_kind":"dns","finding_class":"posture",
            "confidence":1.0,"status":"confirmed","verdict":verdict,
            "verdict_tag":tag,"id":h,"reportable":verdict>=3}
rows=[vid("ok","x.id",0,"L0 OBSERVED - LEAD")]
open(sys.argv[1],"w").write(json.dumps({"ok":True,"data":{},"findings":rows}))
"#;
        let mut skills = Vec::new();
        for (i, _nm) in ["s1", "s2"].iter().enumerate() {
            skills.push(serde_json::json!({
                "name": format!("s{}", i + 1),
                "cmd": ["python", "-c", script, "@OUT@"],
                "safety_class": "read-only",
                "needs": "none"
            }));
        }
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": skills}).to_string(),
        )
        .unwrap();
        let p = ScanParams {
            mode: "tier0".into(),
            target: None,
            domain: None,
            evidence: None,
            source: None,
            out_dir: tmp.join("out"),
            registry: reg_path,
            report: false,
            dry_run: false,
            max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None,
        };
        let r = run_scan(&p).expect("scan harus sukses");
        assert_eq!(r.skills_run.len(), 2);
        // FAO: dua skill menulis temuan IDENTIK -> terdedup jadi 1
        // (dup_count=2) — bukti FAO jalan di pipa nyata
        assert_eq!(r.total_findings, 1);
        let doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&r.merged_path).unwrap(),
        )
        .unwrap();
        assert_eq!(doc["ok"], serde_json::json!(true));
        let arr = doc["findings"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["dup_count"], serde_json::json!(2));
        assert!(arr[0]["evidence_hash"].is_string(), "evidence hash wajib ada");
        assert!(tmp.join("out").join("run-manifest.json").exists(),
                "run-manifest.json wajib ditulis");
        // hardened: data.sources harus per-skill objects dengan requests
        let sources = doc["data"]["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources[0].get("requests").is_some());
        assert!(sources[0].get("skill").is_some());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn source_skills_selected_only_with_source_param() {
        // F70: skill needs=source hanya terpilih bila --source diset
        let reg = Registry {
            version: 1,
            skills: vec![
                SkillSpec { name: "cfg".into(), cmd: vec!["python".into()], safety_class: "read-only".into(), needs: "source".into(), requires_evidence: false, lab_only: false },
                SkillSpec { name: "web".into(), cmd: vec!["python".into()], safety_class: "read-only".into(), needs: "target".into(), requires_evidence: false, lab_only: false },
            ],
        };
        let base = |source: Option<String>| ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None,
            source,
            out_dir: PathBuf::from("x"), registry: PathBuf::from("x"),
            report: false, dry_run: false, max_requests: DEFAULT_MAX_REQUESTS,
            ua: None, proxy: None, proxies_file: None,
        };
        let allowed = allowed_safety_classes("tier0").unwrap();
        assert!(select_skills(&reg, &base(None), &allowed).is_empty(),
                "tanpa --source tidak ada skill source yang terpilih");
        let sel = select_skills(&reg, &base(Some("src".into())), &allowed);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].name, "cfg");
    }

    #[test]
    fn registry_rejects_source_need_without_param_is_selection_only() {
        // needs=source adalah nilai sah di registry (validasi registry lolos)
        let reg = Registry {
            version: 1,
            skills: vec![SkillSpec { name: "cfg".into(), cmd: vec!["python".into(), "skills/x.py".into()], safety_class: "read-only".into(), needs: "source".into(), requires_evidence: false, lab_only: false }],
        };
        assert!(validate_registry(&reg).is_ok());
    }

    #[test]
    fn scan_fails_closed_on_budget_overflow() {
        // audit 2026-10: dulu overflow hanya di-WARN dan scan lanjut —
        // sekarang pelanggaran budget menghentikan run (fail-closed)
        let tmp = std::env::temp_dir().join(format!("cyphron_bof_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        let script = r#"import json,sys,hashlib
h=hashlib.sha256(f"t|ok|x.id||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{},"requests":50,
  "findings":[{"tool":"t","title":"ok","severity":"info","description":"d",
  "target_url":"x.id","evidence_kind":"dns","finding_class":"posture",
  "confidence":1.0,"status":"confirmed","verdict":0,
  "verdict_tag":"L0 OBSERVED - LEAD","id":h,"reportable":False}]}, open(sys.argv[1],"w"))
"#;
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [{
                "name": "boros", "cmd": ["python", "-c", script, "@OUT@"],
                "safety_class": "bounded-requests", "needs": "none"}]}).to_string(),
        )
        .unwrap();
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false,
            dry_run: false, max_requests: 10, ua: None, proxy: None, proxies_file: None,
        };
        let err = run_scan(&p).expect_err("overflow harus menggagalkan run");
        assert!(err.contains("budget-request terlampaui"), "got: {err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn tier0_rejects_untracked_request_skills() {
        // audit 2026-10: skill yang tidak melacak request-nya sendiri
        // = budget tak bisa ditegakkan — tier0 menolak (fail-closed)
        let tmp = std::env::temp_dir().join(format!("cyphron_untracked_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        let script = r#"import json,sys,hashlib
h=hashlib.sha256(f"t|ok|x.id||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{"requests_untracked":True},"requests":0,
  "findings":[{"tool":"t","title":"ok","severity":"info","description":"d",
  "target_url":"x.id","evidence_kind":"dns","finding_class":"posture",
  "confidence":1.0,"status":"confirmed","verdict":0,
  "verdict_tag":"L0 OBSERVED - LEAD","id":h,"reportable":False}]}, open(sys.argv[1],"w"))
"#;
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [{
                "name": "gelap", "cmd": ["python", "-c", script, "@OUT@"],
                "safety_class": "read-only", "needs": "none"}]}).to_string(),
        )
        .unwrap();
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false,
            dry_run: false, max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None,
        };
        let err = run_scan(&p).expect_err("untracked requests harus ditolak di tier0");
        assert!(err.contains("requests_untracked"), "got: {err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn scan_fails_closed_on_contract_violation() {
        let tmp = std::env::temp_dir().join(format!("cyphron_scanbad_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        let script = r#"import json,sys
json.dump({"ok":True,"data":{},"findings":[{"tool":"t","title":"x",
  "severity":"gila","verdict":1,"verdict_tag":"SALAH","id":"00",
  "reportable":True}]}, open(sys.argv[1],"w"))
"#;
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [{
                "name": "bad", "cmd": ["python", "-c", script, "@OUT@"],
                "safety_class": "read-only", "needs": "none"}]}).to_string(),
        )
        .unwrap();
        let p = ScanParams {
            mode: "tier0".into(),
            target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false, dry_run: false, max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None,
        };
        assert!(run_scan(&p).is_err(), "kontrak rusak harus menghentikan scan");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn active_probe_runs_only_in_lab_mode() {
        // dua skill: read-only + active-probe (keduanya valid).
        // tier0: hanya read-only yang boleh jalan. lab: keduanya.
        let tmp = std::env::temp_dir().join(format!("cyphron_gate_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        let script = r#"import json,sys,hashlib
h=hashlib.sha256(f"t|ok|x.id||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{},"findings":[{"tool":"t","title":"ok",
  "severity":"info","description":"d","target_url":"x.id","evidence_kind":"dns",
  "finding_class":"posture","confidence":1.0,"status":"confirmed","verdict":0,
  "verdict_tag":"L0 OBSERVED - LEAD","id":h,"reportable":False}]}, open(sys.argv[1],"w"))
"#;
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [
                {"name": "safe", "cmd": ["python", "-c", script, "@OUT@"],
                 "safety_class": "read-only", "needs": "none"},
                {"name": "probe", "cmd": ["python", "-c", script, "@OUT@"],
                 "safety_class": "active-probe", "needs": "none"},
            ]}).to_string(),
        )
        .unwrap();
        let base = |mode: &str| ScanParams {
            mode: mode.into(),
            target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join(format!("out-{mode}")),
            registry: reg_path.clone(), report: false, dry_run: false, max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None,
        };
        let t0 = run_scan(&base("tier0")).expect("tier0 harus jalan");
        assert_eq!(t0.skills_run, vec!["safe".to_string()],
                   "active-probe TIDAK boleh jalan di tier0");
        let l0 = run_scan(&base("lab")).expect("lab harus jalan");
        assert_eq!(l0.skills_run.len(), 2, "di lab keduanya jalan");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn dry_run_prints_without_executing() {
        let tmp = std::env::temp_dir().join(format!("cyphron_dry_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        // skill yang would fail if executed — dry-run must not execute it
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [
                {"name": "safe", "cmd": ["python", "-c", "import sys; sys.exit(99)", "@OUT@"],
                 "safety_class": "read-only", "needs": "none"},
            ]}).to_string(),
        ).unwrap();
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false, dry_run: true, max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None,
        };
        let r = run_scan(&p).expect("dry-run harus sukses tanpa eksekusi");
        assert_eq!(r.skills_run.len(), 1);
        assert_eq!(r.requests, 0);
        assert_eq!(r.total_findings, 0);
        // dry-run must not create findings.json
        assert!(!tmp.join("out").join("findings.json").exists(), "dry-run tidak boleh menulis file");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn requests_top_authoritative_data_is_fallback() {
        // Kontrak write_findings menulis angka SAMA di top & data.requests —
        // menghitung keduanya = dobel. Top otoritatif; data hanya fallback.
        let tmp = std::env::temp_dir().join(format!("cyphron_reqsum_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        // skill menulis top=3 dan data.requests=3 (angka sama, kasus nyata)
        let script = r#"import json,sys,hashlib
h=hashlib.sha256(f"t|ok|x.id||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{"requests":3},"requests":3,"findings":[{"tool":"t","title":"ok",
  "severity":"info","description":"d","target_url":"x.id","evidence_kind":"dns",
  "finding_class":"posture","confidence":1.0,"status":"confirmed","verdict":0,
  "verdict_tag":"L0 OBSERVED - LEAD","id":h,"reportable":False}]}, open(sys.argv[1],"w"))
"#;
        // varian tanpa top-level (fallback ke data.requests)
        let script2 = r#"import json,sys,hashlib
h=hashlib.sha256(f"t|ok|x.id||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{"requests":2},"findings":[{"tool":"t","title":"ok",
  "severity":"info","description":"d","target_url":"x.id","evidence_kind":"dns",
  "finding_class":"posture","confidence":1.0,"status":"confirmed","verdict":0,
  "verdict_tag":"L0 OBSERVED - LEAD","id":h,"reportable":False}]}, open(sys.argv[1],"w"))
"#;
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [
                {"name": "s1", "cmd": ["python", "-c", script, "@OUT@"],
                 "safety_class": "read-only", "needs": "none"},
                {"name": "s2", "cmd": ["python", "-c", script2, "@OUT@"],
                 "safety_class": "read-only", "needs": "none"},
            ]}).to_string(),
        ).unwrap();
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false, dry_run: false, max_requests: DEFAULT_MAX_REQUESTS, ua: None, proxy: None, proxies_file: None,
        };
        let r = run_scan(&p).expect("scan harus sukses");
        assert_eq!(r.requests, 5, "s1 top=3 (bukan 3+3) + s2 fallback data=2");
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&r.merged_path).unwrap()).unwrap();
        assert_eq!(doc["requests"], serde_json::json!(5));
        assert_eq!(doc["data"]["sources"][0]["requests"], serde_json::json!(3));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn estimate_max_requests_by_class() {
        assert_eq!(estimate_max_requests("read-only"), 0);
        assert_eq!(estimate_max_requests("1-request"), 1);
        assert_eq!(estimate_max_requests("bounded-requests"), 5);
        assert_eq!(estimate_max_requests("active-probe"), usize::MAX);
    }

    #[test]
    fn low_profile_env_reaches_skill_process() {
        // F20: --ua/--proxy diinjeksikan sebagai env ke proses skill;
        // skill mencatat nilai env itu ke data.meta — diverifikasi balik.
        let tmp = std::env::temp_dir().join(format!("cyphron_ua_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        let script = r#"import json,sys,os,hashlib
h=hashlib.sha256(f"t|ok|x.id||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{"ua":os.environ.get("CYPHRON_UA","(none)"),
  "https_proxy":os.environ.get("HTTPS_PROXY","(none)")},"requests":0,
  "findings":[{"tool":"t","title":"ok","severity":"info","description":"d",
  "target_url":"x.id","evidence_kind":"dns","finding_class":"posture",
  "confidence":1.0,"status":"confirmed","verdict":0,
  "verdict_tag":"L0 OBSERVED - LEAD","id":h,"reportable":False}]}, open(sys.argv[1],"w"))
"#;
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [
                {"name": "s1", "cmd": ["python", "-c", script, "@OUT@"],
                 "safety_class": "read-only", "needs": "none"},
            ]}).to_string(),
        ).unwrap();
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false,
            dry_run: false, max_requests: DEFAULT_MAX_REQUESTS,
            ua: Some("browser".into()),
            proxy: Some("http://127.0.0.1:18080".into()),
            proxies_file: None,
        };
        let r = run_scan(&p).expect("scan harus sukses");
        // env yang dilihat SKILL tercatat di file output per-skill;
        // merged doc membawa metadata low_profile milik orchestrator.
        let skill_doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(tmp.join("out").join("s1.json")).unwrap(),
        ).unwrap();
        assert!(skill_doc["data"]["ua"].as_str().unwrap_or("")
                    .starts_with("browser"),
                "env CYPHRON_UA (nilai mentah --ua) harus sampai ke skill; \
                 ekspansi profil browser terjadi di skills/ua.py");
        assert_eq!(skill_doc["data"]["https_proxy"],
                   serde_json::json!("http://127.0.0.1:18080"));
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&r.merged_path).unwrap()).unwrap();
        let data = &doc["data"];
        assert_eq!(data["low_profile"]["proxy"], serde_json::json!(true));
        assert_eq!(data["low_profile"]["ua"], serde_json::json!("browser"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn proxy_pool_round_robin_reaches_skill_processes() {
        // F20b: dua skill, dua proxy -> masing-masing skill melihat
        // HTTPS_PROXY berbeda (round-robin deterministik) + audit
        // per-skill tercatat di data.sources (kredensial direduksi).
        let tmp = std::env::temp_dir().join(format!("cyphron_pxrot_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        let script = r#"import json,sys,os,hashlib
h=hashlib.sha256(f"t|ok|x.id||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{"https_proxy":os.environ.get("HTTPS_PROXY","(none)")},
  "requests":0,"findings":[{"tool":"t","title":"ok","severity":"info",
  "description":"d","target_url":"x.id","evidence_kind":"dns",
  "finding_class":"posture","confidence":1.0,"status":"confirmed",
  "verdict":0,"verdict_tag":"L0 OBSERVED - LEAD","id":h,
  "reportable":False}]}, open(sys.argv[1],"w"))
"#;
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [
                {"name": "s1", "cmd": ["python", "-c", script, "@OUT@"],
                 "safety_class": "read-only", "needs": "none"},
                {"name": "s2", "cmd": ["python", "-c", script, "@OUT@"],
                 "safety_class": "read-only", "needs": "none"},
            ]}).to_string(),
        ).unwrap();
        let px_file = tmp.join("proxies.txt");
        std::fs::write(&px_file, "# egress pool
http://user:secret@10.0.0.1:9001

http://10.0.0.2:9002
").unwrap();
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false,
            dry_run: false, max_requests: DEFAULT_MAX_REQUESTS,
            ua: None, proxy: None,
            proxies_file: Some(px_file.to_string_lossy().to_string()),
        };
        let r = run_scan(&p).expect("scan harus sukses");
        let out = tmp.join("out");
        let s1: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(out.join("s1.json")).unwrap()).unwrap();
        let s2: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(out.join("s2.json")).unwrap()).unwrap();
        assert_eq!(s1["data"]["https_proxy"], serde_json::json!("http://user:secret@10.0.0.1:9001"));
        assert_eq!(s2["data"]["https_proxy"], serde_json::json!("http://10.0.0.2:9002"));
        let doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&r.merged_path).unwrap()).unwrap();
        assert_eq!(doc["data"]["low_profile"]["proxy_count"], serde_json::json!(2));
        assert_eq!(doc["data"]["low_profile"]["strategy"],
                   serde_json::json!("round-robin-per-skill"));
        let sources = doc["data"]["sources"].as_array().unwrap();
        // kredensial user:secret TIDAK boleh bocor ke merged doc
        assert_eq!(sources[0]["proxy"], serde_json::json!("http://***@10.0.0.1:9001"));
        assert_eq!(sources[1]["proxy"], serde_json::json!("http://10.0.0.2:9002"));
        let raw = std::fs::read_to_string(&r.merged_path).unwrap();
        assert!(!raw.contains("user:secret"), "kredensial proxy tidak boleh masuk merged doc");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn proxy_pool_fail_closed_and_conflict() {
        // file berisi baris tidak valid -> error keras
        let tmp = std::env::temp_dir().join(format!("cyphron_pxfail_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let bad = tmp.join("bad.txt");
        std::fs::write(&bad, "http://ok:1
garbage-tanpa-skema
").unwrap();
        assert!(load_proxy_pool(bad.to_str().unwrap()).is_err());
        // file kosong -> error
        let empty = tmp.join("empty.txt");
        std::fs::write(&empty, "# hanya komentar

").unwrap();
        assert!(load_proxy_pool(empty.to_str().unwrap()).is_err());
        // --proxy + --proxies bersamaan -> error (konflik egress)
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: PathBuf::from("x"), registry: PathBuf::from("x"),
            report: false, dry_run: false, max_requests: DEFAULT_MAX_REQUESTS,
            ua: None, proxy: Some("http://a:1".into()),
            proxies_file: Some("x.txt".into()),
        };
        let err = run_scan(&p).unwrap_err();
        assert!(err.contains("fail-closed"), "got: {err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn budget_zero_fails_closed() {
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: PathBuf::from("x"), registry: PathBuf::from("x"),
            report: false, dry_run: false, max_requests: 0, ua: None, proxy: None, proxies_file: None,
        };
        let err = run_scan(&p).unwrap_err();
        assert!(err.contains("fail-closed"), "got: {err}");
    }

    #[test]
    fn budget_skips_skill_with_audit_line() {
        // dua skill 1-request, cap = 1 -> skill kedua di-skip dengan baris
        // audit + tercatat di data.budget.skipped
        let tmp = std::env::temp_dir().join(format!("cyphron_budget_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        let script = r#"import json,sys,hashlib
h=hashlib.sha256(f"t|ok|x.id||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{"requests":1},"requests":1,"findings":[{"tool":"t","title":"ok",
  "severity":"info","description":"d","target_url":"x.id","evidence_kind":"dns",
  "finding_class":"posture","confidence":1.0,"status":"confirmed","verdict":0,
  "verdict_tag":"L0 OBSERVED - LEAD","id":h,"reportable":False}]}, open(sys.argv[1],"w"))
"#;
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [
                {"name": "satu", "cmd": ["python", "-c", script, "@OUT@"],
                 "safety_class": "1-request", "needs": "none"},
                {"name": "dua", "cmd": ["python", "-c", script, "@OUT@"],
                 "safety_class": "1-request", "needs": "none"},
            ]}).to_string(),
        ).unwrap();
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false,
            dry_run: false, max_requests: 1, ua: None, proxy: None, proxies_file: None,
        };
        let r = run_scan(&p).expect("scan harus tetap sukses (satu skill jalan)");
        assert_eq!(r.skills_run, vec!["satu".to_string()]);
        assert_eq!(r.skipped_budget, vec!["dua".to_string()]);
        assert_eq!(r.requests, 1);
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&r.merged_path).unwrap()).unwrap();
        assert_eq!(doc["data"]["budget"]["max_requests"], serde_json::json!(1));
        assert_eq!(doc["data"]["budget"]["skipped"], serde_json::json!(["dua"]));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn budget_exhausting_all_skills_fails_closed() {
        // satu skill bounded-requests (est 5), cap 1 -> di-skip semua ->
        // run gagal (bukan sukses kosong yang menyesatkan triage)
        let tmp = std::env::temp_dir().join(format!("cyphron_budgetall_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let reg_path = tmp.join("registry.json");
        std::fs::write(
            &reg_path,
            serde_json::json!({"version": 1, "skills": [
                {"name": "berat", "cmd": ["python", "-c", "pass"],
                 "safety_class": "bounded-requests", "needs": "none"},
            ]}).to_string(),
        ).unwrap();
        let p = ScanParams {
            mode: "tier0".into(), target: None, domain: None, evidence: None, source: None,
            out_dir: tmp.join("out"), registry: reg_path, report: false,
            dry_run: false, max_requests: 1, ua: None, proxy: None, proxies_file: None,
        };
        let err = run_scan(&p).unwrap_err();
        assert!(err.contains("fail-closed"), "got: {err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
