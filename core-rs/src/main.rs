//! Cyphron core CLI (working title) — engine runner + kontrak findings.
//!
//! Perintah:
//!   cyphron validate <file.json>            — validasi findings.json vs kontrak
//!   cyphron run --out <file> <skill...>     — jalankan skill (subproses),
//!     placeholder @OUT@ di argv diganti path output absolut
//!   cyphron info                            — kontrak ringkas + versi
//!
//! Fail-closed: exit != 0 kalau kontrak dilanggar.

mod contract;
mod fao;
mod orchestrator;
mod runner;
mod serve;
mod worker;

use contract::{FindingsDoc, MIN_REPORT_LEVEL};
use std::path::PathBuf;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("validate") => cmd_validate(args.get(1)),
        Some("run") => cmd_run(&args[1..]),
        Some("merge") => cmd_merge(&args[1..]),
        Some("worker") => cmd_worker(&args[1..]),
        Some("serve") => cmd_serve(&args[1..]),
        Some("scan") => std::process::exit(orchestrator::cmd_scan(&args[1..])),
        Some("nightrun") => cmd_nightrun(&args[1..]),
        Some("queue") => cmd_queue(&args[1..]),
        Some("export") => cmd_export(&args[1..]),
        Some("info") | None => cmd_info(),
        Some("--version") | Some("-V") => {
            println!("cyphron/0.1.0 core-findings");
        }
        Some(other) => {
            eprintln!("unknown command: {other}");
            cmd_info();
            exit(2);
        }
    }
}

fn cmd_merge(args: &[String]) {
    let mut out: Option<PathBuf> = None;
    let mut inputs: Vec<PathBuf> = Vec::new();
    // Dedup lintas-mode: run tier0 + lab pada target sama menghasilkan
    // baris id identik — tanpa dedup, gabungan dobel menyesatkan triage.
    // Opt-in agar perilaku lama tidak berubah diam-diam (sama seperti
    // tools/merge_findings.py --dedup-id).
    let mut dedup_id = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out = Some(PathBuf::from(
                    args.get(i + 1).map(String::as_str).unwrap_or_default(),
                ));
                i += 2;
            }
            "--dedup-id" => {
                dedup_id = true;
                i += 1;
            }
            p => {
                inputs.push(PathBuf::from(p));
                i += 1;
            }
        }
    }
    let out = out.unwrap_or_else(|| {
        eprintln!("usage: cyphron merge --out <file> [--dedup-id] <input1.json> <input2.json> ...");
        exit(2);
    });
    let mut findings: Vec<contract::Finding> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    for inp in &inputs {
        match runner::validate_file(inp) {
            Ok((n, errs)) if errs.is_empty() => {
                let doc: FindingsDoc = serde_json::from_str(
                    &std::fs::read_to_string(inp).unwrap_or_default(),
                )
                .expect("re-read after validation");
                findings.extend(doc.findings);
                sources.push(inp.display().to_string());
                println!("+ {} ({n} findings)", inp.display());
            }
            Ok((_, errs)) => {
                for e in &errs {
                    eprintln!("INVALID in {}: {e}", inp.display());
                }
                exit(1);
            }
            Err(e) => {
                eprintln!("ERROR: {e}");
                exit(1);
            }
        }
    }
    let dedup_dropped = if dedup_id {
        let dropped = fao::dedup_by_id(&mut findings);
        println!("dedup-id: {} duplikat dibuang (baris pertama dipertahankan)", dropped);
        Some(dropped)
    } else {
        None
    };
    if let Err(e) = runner::write_merged(&out, &sources, &findings, 0, dedup_dropped) {
        eprintln!("ERROR writing: {e}");
        exit(1);
    }
    let note = dedup_dropped
        .map(|n| format!(" (dedup: {n} duplikat dibuang)"))
        .unwrap_or_default();
    println!("merged: {} findings{note} -> {}", findings.len(), out.display());
}

/// F23 — delegasi `cyphron nightrun` ke tools/nightrun.py (orchestrator
/// Python: config + budget per target + drift by ID + weekly + PDF).
/// Logika orchestrator tinggal di satu tempat (Python, teruji); binari
/// Rust hanya titik masuk CLI. Fail-closed: script tidak ada / python
/// tidak bisa di-spawn = exit 1 dengan pesan jelas.
fn cmd_nightrun(args: &[String]) {
    let python = std::env::var("CYPHRON_PYTHON").unwrap_or_else(|_| "python".into());
    let script = PathBuf::from("tools").join("nightrun.py");
    if !script.exists() {
        eprintln!(
            "ERROR: {} tidak ditemukan — jalankan dari root repo (fail-closed)",
            script.display()
        );
        exit(1);
    }
    let status = std::process::Command::new(&python)
        .arg(&script)
        .args(args)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("ERROR: tidak bisa spawn '{python}': {e} — set env CYPHRON_PYTHON");
            exit(1);
        });
    exit(status.code().unwrap_or(1));
}

fn cmd_worker(args: &[String]) {
    let mut url = "nats://127.0.0.1:4222".to_string();
    let mut subject = "scans.q".to_string();
    let mut workdir = std::env::current_dir().unwrap_or_default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--nats" => { url = args.get(i + 1).cloned().unwrap_or(url); i += 2; }
            "--subject" => { subject = args.get(i + 1).cloned().unwrap_or(subject); i += 2; }
            "--workdir" => { workdir = PathBuf::from(args.get(i + 1).map(String::as_str).unwrap_or(".")); i += 2; }
            other => { eprintln!("unknown flag: {other}"); exit(2); }
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let err_log = workdir.join("worker-errors.log");
    if let Err(e) = rt.block_on(worker::worker_loop(&url, &subject, &workdir, &err_log)) {
        eprintln!("ERROR: {e}");
        exit(1);
    }
}

fn cmd_serve(args: &[String]) {
    let mut dir = PathBuf::from("findings");
    let mut port = 8900u16;
    let mut auth: Option<serve::Auth> = None;
    let mut audit_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => { dir = PathBuf::from(args.get(i + 1).map(String::as_str).unwrap_or("findings")); i += 2; }
            "--port" => { port = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(8900); i += 2; }
            "--token" => {
                auth = Some(serve::Auth::from_single(
                    args.get(i + 1).map(String::as_str).unwrap_or_default()));
                i += 2;
            }
            "--auth-file" => {
                match serve::Auth::from_file(&PathBuf::from(
                    args.get(i + 1).map(String::as_str).unwrap_or_default(),
                )) {
                    Ok(a) => auth = Some(a),
                    Err(e) => { eprintln!("ERROR: {e}"); exit(1); }
                }
                i += 2;
            }
            "--audit-file" => { audit_path = Some(PathBuf::from(args.get(i + 1).map(String::as_str).unwrap_or("auth/audit.log"))); i += 2; }
            other => { eprintln!("unknown flag: {other}"); exit(2); }
        }
    }
    if let Err(e) = serve::serve_loop(&dir, port, auth, audit_path) {
        eprintln!("ERROR: {e}");
        exit(1);
    }
}

/// F12 — antrikan rencana scan ke worker (NATS JetStream) tanpa
/// menjalankan skill di mesin ini. Satu job per skill terpilih.
fn cmd_queue(args: &[String]) {
    let mut url = "nats://127.0.0.1:4222".to_string();
    let mut subject = "scans.q".to_string();
    let mut p = orchestrator::ScanParams {
        mode: "tier0".into(),
        target: None, domain: None, evidence: None, source: None,
        out_dir: PathBuf::from(format!("findings/queued/manual-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0))),
        registry: PathBuf::from("skills/registry.json"),
        report: false,
        dry_run: false,
        max_requests: orchestrator::DEFAULT_MAX_REQUESTS,
        ua: None,
        proxy: None,
        proxies_file: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--nats" => { url = args.get(i+1).cloned().unwrap_or(url); i += 2; }
            "--subject" => { subject = args.get(i+1).cloned().unwrap_or(subject); i += 2; }
            "--mode" => { p.mode = args.get(i+1).cloned().unwrap_or(p.mode); i += 2; }
            "--target" => { p.target = args.get(i+1).cloned(); i += 2; }
            "--domain" => { p.domain = args.get(i+1).cloned(); i += 2; }
            "--evidence" => { p.evidence = args.get(i+1).cloned(); i += 2; }
            "--out" => { p.out_dir = PathBuf::from(args.get(i+1).map(String::as_str).unwrap_or_default()); i += 2; }
            "--lab" => { p.mode = "lab".into(); i += 1; }
            "--max-requests" => {
                match args.get(i+1).and_then(|v| v.parse::<usize>().ok()) {
                    Some(n) if n > 0 => { p.max_requests = n; i += 2; }
                    _ => { eprintln!("--max-requests butuh integer >= 1 — fail-closed"); exit(2); }
                }
            }
            other => { eprintln!("unknown flag: {other}"); exit(2); }
        }
    }
    let reg = match orchestrator::load_registry(&p.registry) {
        Ok(r) => r,
        Err(e) => { eprintln!("ERROR: {e}"); exit(1); }
    };
    let allowed = match orchestrator::allowed_safety_classes(&p.mode) {
        Ok(a) => a,
        Err(e) => { eprintln!("ERROR: {e}"); exit(1); }
    };
    let selected = orchestrator::select_skills(&reg, &p, &allowed);
    if selected.is_empty() {
        eprintln!("ERROR: tidak ada skill yang cocok — fail-closed");
        exit(1);
    }
    let count = selected.len();
    let (url2, subject2) = (url.clone(), subject.clone());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all().build().expect("tokio runtime");
    rt.block_on(async move {
        let client = match async_nats::connect(&url2).await {
            Ok(c) => c,
            Err(e) => { eprintln!("ERROR: connect {url2}: {e}"); exit(1); }
        };
        let js = async_nats::jetstream::new(client);
        let stream_name = subject2.split('.').next().unwrap_or("scans").to_uppercase();
        let _ = js.get_or_create_stream(async_nats::jetstream::stream::Config {
            name: stream_name.clone(),
            subjects: vec![subject2.clone()],
            ..Default::default()
        }).await;
        for s in &selected {
            let out_path = p.out_dir.join(format!("{}.json", s.name));
            let cmd: Vec<String> = s.cmd.iter()
                .map(|a| a
                    .replace("@TARGET@", p.target.as_deref().unwrap_or(""))
                    .replace("@DOMAIN@", p.domain.as_deref().unwrap_or(""))
                    .replace("@EVIDENCE@", p.evidence.as_deref().unwrap_or(""))
                    .replace("@OUT@", &out_path.to_string_lossy().to_string()))
                .collect();
            let job = serde_json::json!({
                "job_id": format!("queue-{}", s.name),
                "cmd": cmd,
                "out": out_path.to_string_lossy(),
            });
            let bytes: Vec<u8> = serde_json::to_vec(&job).unwrap();
            match js.publish(subject2.clone(), bytes.into()).await {
                Ok(_) => println!("queued: {} -> {} ({})", s.name, subject2,
                                  out_path.display()),
                Err(e) => { eprintln!("ERROR publish: {e}"); exit(1); }
            }
        }
    });
    println!("{count} job diantrikan ke {url} ({subject})");
}

/// F12 — export findings.json ke format GRC (CSV) atau JSON rapi.
fn cmd_export(args: &[String]) {
    let mut findings_path: Option<PathBuf> = None;
    let mut format = "csv".to_string();
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--findings" => { findings_path = Some(PathBuf::from(args.get(i+1).map(String::as_str).unwrap_or_default())); i += 2; }
            "--format" => { format = args.get(i+1).cloned().unwrap_or(format); i += 2; }
            "--out" => { out = Some(PathBuf::from(args.get(i+1).map(String::as_str).unwrap_or_default())); i += 2; }
            other => { eprintln!("unknown flag: {other}"); exit(2); }
        }
    }
    let fp = findings_path.unwrap_or_else(|| { eprintln!("usage: cyphron export --findings <f.json> --format csv|json --out <file>"); exit(2); });
    let raw = std::fs::read_to_string(&fp).unwrap_or_else(|e| { eprintln!("ERROR: {e}"); exit(1); });
    let doc: contract::FindingsDoc = serde_json::from_str(&raw)
        .unwrap_or_else(|e| { eprintln!("ERROR: bukan findings.json: {e}"); exit(1); });
    let out = out.unwrap_or_else(|| fp.with_extension(match format.as_str() { "csv" => "csv", _ => "export.json" }));
    if format == "csv" {
        let mut rows = Vec::new();
        rows.push("id,tool,title,severity,verdict_tag,target,category,cwe,quorum,evidence_hash".to_string());
        for f in &doc.findings {
            let esc = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
            rows.push(vec![
                f.id.clone(),
                esc(&f.tool),
                esc(&f.title),
                f.severity.clone(),
                esc(&f.verdict_tag),
                esc(f.target_url.as_deref().unwrap_or("")),
                esc(f.extra.get("category").and_then(|v| v.as_str()).unwrap_or("")),
                esc(f.cwe.as_deref().unwrap_or("")),
                f.extra.get("quorum").map(|v| v.to_string()).unwrap_or_default(),
                f.extra.get("evidence_hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            ].join(","));
        }
        std::fs::write(&out, rows.join("\r\n") + "\r\n").unwrap_or_else(|e| { eprintln!("ERROR: {e}"); exit(1); });
    } else {
        let pretty = serde_json::to_vec_pretty(&doc).unwrap_or_else(|e| { eprintln!("ERROR: {e}"); exit(1); });
        std::fs::write(&out, pretty).unwrap_or_else(|e| { eprintln!("ERROR: {e}"); exit(1); });
    }
    println!("export: {} findings -> {} ({})", doc.findings.len(), out.display(), format);
}

fn cmd_info() {
    println!(
        "cyphron core 0.1.0 — findings contract satu pintu
verdict ladder: 0 OBSERVED, 1 SUSPECTED, 2 REPRODUCED, 3 DETERMINISTICALLY_VERIFIED,
                4 IMPACT_VERIFIED, 5 BLIND_VALIDATED, -1 REJECTED
min report level: {MIN_REPORT_LEVEL} (di bawahnya = LEAD)
perintah: validate <file> | run --out <file> <skill...> | merge --out <file> [--dedup-id] <input...> |
          worker --nats <url> --subject <subj> | serve --dir <dir> --port <p> [--token <t>] |
          scan --domain <d> [--target <u>] [--mode tier0|lab] [--evidence <f>] [--report] |
          nightrun --config <f> [--out <dir>] [--no-pdf] [--dry-run] | info"
    );
}

fn cmd_validate(path: Option<&String>) {
    let p = match path {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: cyphron validate <file.json>");
            exit(2);
        }
    };
    match runner::validate_file(&p) {
        Ok((n, errs)) if errs.is_empty() => {
            println!("OK: {n} findings valid terhadap kontrak ({p:?})");
        }
        Ok((_, errs)) => {
            for e in &errs {
                eprintln!("INVALID: {e}");
            }
            exit(1);
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            exit(1);
        }
    }
}

fn cmd_run(args: &[String]) {
    // Parser: flag cyphron hanya SEBELUM `--` (atau sebelum token pertama
    // perintah skill). Semua setelahnya verbatim milik skill — flag skill
    // (mis. --out @OUT@) TIDAK boleh diinterpretasi ulang (bug #1: arm
    // "--out" tanpa guard menelan flag skill dan mengosongkan output).
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out = Some(PathBuf::from(
                    args.get(i + 1).map(String::as_str).unwrap_or_default(),
                ));
                i += 2;
            }
            "--" => {
                i += 1;
                break;
            }
            s if s.starts_with('-') => {
                eprintln!("unknown flag: {s}");
                exit(2);
            }
            _ => break, // token pertama perintah skill
        }
    }
    let skill: Vec<String> = args[i.min(args.len())..].to_vec();
    let out = out.unwrap_or_else(|| {
        eprintln!("usage: cyphron run --out <file> <skill...> (pakai @OUT@ placeholder)");
        exit(2);
    });
    if skill.is_empty() {
        eprintln!("no skill command given");
        exit(2);
    }
    match runner::run_skill(&skill, &out, None) {
        Ok(res) if res.ok => {
            println!(
                "OK: {} findings valid (exit {:?}) -> {}",
                res.findings,
                res.exit_code,
                out.display()
            );
        }
        Ok(res) => {
            for e in &res.invalid {
                eprintln!("INVALID: {e}");
            }
            exit(1);
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            exit(1);
        }
    }
}
