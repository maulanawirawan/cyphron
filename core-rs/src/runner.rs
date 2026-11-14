//! Skill runner: eksekusi skill (Python atau lainnya) sebagai subproses,
//! lalu buka findings.json hasilnya, validasi setiap baris terhadap
//! kontrak, dan tulis SATU findings.json (satu pintu).
//! Fail-closed: skill gagal / output tidak valid = error keras, bukan
//! output kosong yang diemte.

use crate::contract::{Finding, FindingsDoc};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const SKILL_TIMEOUT_SECS: u64 = 120;
const MAX_FINDINGS_BYTES: u64 = 16 * 1024 * 1024;

/// Helper: spawn argv with timeout, kill on timeout, capture stderr truncated to 2 KiB.
fn run_with_timeout(
    argv: &[String],
    workdir: Option<&Path>,
    timeout_secs: u64,
    extra_env: &[(String, String)],
) -> Result<(std::process::ExitStatus, String), String> {
    if argv.is_empty() {
        return Err("no skill command given".to_string());
    }
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(workdir.unwrap_or(Path::new(".")))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot spawn '{}': {e}", argv[0]))?;

    // Take stderr pipe and drain in background thread to avoid deadlock on full buffer.
    let mut stderr_pipe = child.stderr.take();
    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let buf_clone = stderr_buf.clone();
    let reader = std::thread::spawn(move || {
        if let Some(mut pipe) = stderr_pipe.take() {
            let mut v = Vec::new();
            let _ = std::io::Read::read_to_end(&mut pipe, &mut v);
            *buf_clone.lock().unwrap() = v;
        }
    });

    let timeout = Duration::from_secs(timeout_secs);
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(format!(
                        "skill timeout after {}s: {}",
                        timeout_secs, argv[0]
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = reader.join();
                return Err(format!("wait error: {e}"));
            }
        }
    };

    let _ = reader.join();
    let raw = stderr_buf.lock().unwrap().clone();
    let s = String::from_utf8_lossy(&raw).to_string();
    let truncated = if s.len() > 2048 {
        format!("{}...<truncated 2KiB>", &s[..2048])
    } else {
        s
    };
    Ok((status, truncated))
}

#[derive(Debug)]
pub struct RunResult {
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub findings: usize,
    pub invalid: Vec<String>,
    pub skill_outputs: Vec<PathBuf>,
}

/// Jalankan satu skill: skill_argv[0] = program, sisanya argumen.
/// Skill wajib menulis findings.json di path yang kita tentukan lewat
/// placeholder `@OUT@` di argv (diganti path absolut output).
pub fn run_skill(
    skill_argv: &[String],
    out_path: &Path,
    workdir: Option<&Path>,
) -> Result<RunResult, String> {
    run_skill_with_env(skill_argv, out_path, workdir, &[])
}

/// Sama dengan run_skill + env tambahan untuk proses skill (F20:
/// SECAI_UA untuk profil User-Agent, HTTP(S)_PROXY untuk proxy run).
/// Env menggantikan nilai bawaan bila key sama.
pub fn run_skill_with_env(
    skill_argv: &[String],
    out_path: &Path,
    workdir: Option<&Path>,
    extra_env: &[(String, String)],
) -> Result<RunResult, String> {
    if skill_argv.is_empty() {
        return Err("no skill command given".to_string());
    }
    // Robust absolute resolution — no canonicalize fallback swallowing errors.
    let out_abs: PathBuf = if out_path.is_absolute() {
        out_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(out_path)
    };
    // ensure parent exists before spawn
    if let Some(parent) = out_abs.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Uniform @OUT@ handling: replace all occurrences, warn if zero.
    let out_str = out_abs.display().to_string();
    let at_out_count: usize = skill_argv.iter().map(|a| a.matches("@OUT@").count()).sum();
    if at_out_count == 0 {
        eprintln!("[runner] warning: argv contains no @OUT@ placeholder; out_abs={out_str}");
    }
    let argv: Vec<String> = skill_argv
        .iter()
        .map(|a| a.replace("@OUT@", &out_str))
        .collect();

    let (status, stderr_trunc) =
        run_with_timeout(&argv, workdir, SKILL_TIMEOUT_SECS, extra_env)?;

    if !status.success() {
        return Ok(RunResult {
            ok: false,
            exit_code: status.code(),
            findings: 0,
            invalid: vec![format!(
                "skill exited non-zero: {status} stderr: {stderr_trunc}"
            )],
            skill_outputs: vec![],
        });
    }

    // Size cap: check metadata before reading; if >16 MiB fail hard.
    if let Ok(meta) = std::fs::metadata(&out_abs) {
        if meta.len() > MAX_FINDINGS_BYTES {
            return Err(format!(
                "findings.json too large >16MiB: {} bytes at {:?}",
                meta.len(),
                out_abs
            ));
        }
    }
    // Baca dan validasi output (after timeout and size check)
    let raw = std::fs::read_to_string(&out_abs)
        .map_err(|e| format!("skill did not produce {out_abs:?}: {e}"))?;
    // Defensive second size check on raw string length
    if (raw.len() as u64) > MAX_FINDINGS_BYTES {
        return Err(format!(
            "findings.json too large >16MiB: {} bytes at {:?}",
            raw.len(),
            out_abs
        ));
    }
    let doc: FindingsDoc =
        serde_json::from_str(&raw).map_err(|e| format!("invalid findings.json: {e}"))?;
    if !doc.ok {
        return Err("findings.json says ok=false".to_string());
    }
    let mut invalid = Vec::new();
    for (i, f) in doc.findings.iter().enumerate() {
        if let Err(e) = f.validate() {
            invalid.push(format!("findings[{i}] {}: {e}", f.title));
        }
    }
    let findings = doc.findings.len();
    Ok(RunResult {
        ok: invalid.is_empty(),
        exit_code: status.code(),
        findings,
        invalid,
        skill_outputs: vec![out_abs],
    })
}

pub const GUARD_ENV: &str = "SECAI_NET_GUARD";
pub const BUDGET_ENV: &str = "SECAI_NET_BUDGET_FILE";
pub const AUDIT_ENV: &str = "SECAI_NET_AUDIT";
pub const SCOPE_ENV: &str = "SECAI_NET_SCOPE_FILE";

/// Fase 2-B lanjutan (docs/CONTROLLED-NETWORK.md §3): jalankan skill di
/// bawah net-guard — env diinjeksi, audit diverifikasi, fail-closed.
///
/// - budget file `{limit, used:0}` dibuat runner (milik runner);
/// - PYTHONPATH di-merge: repo root + `tools/net_guard` (sitecustomize
///   memuat `core.net_guard.auto_install_from_env`);
/// - `caller_env`: env tambahan milik pemanggil (UA low-profile, proxy
///   rotasi, dll). Env guard SELALU ditulis SETELAH env pemanggil —
///   pemanggil tidak bisa menimpa/mematikan guard lewat extra_env
///   (SECAI_NET_GUARD=0 dari lupa ter-override -> tetap "1").
/// - setelah skill selesai: audit log WAJIB ada, WAJIB memuat baris
///   `guard-install` (bukti patch socket terpasang di proses skill),
///   semua baris JSON valid, dan `used <= limit` — pelanggaran apa pun
///   = Err (hard-fail), bukan output kosong yang diemte.
pub fn run_skill_guarded(
    skill_argv: &[String],
    out_path: &Path,
    workdir: Option<&Path>,
    budget_limit: usize,
    scope_path: Option<&Path>,
    caller_env: &[(String, String)],
) -> Result<RunResult, String> {
    if budget_limit == 0 {
        return Err(
            "net-guard: budget 0 — tolak sebelum spawn (tidak ada koneksi \
             yang dijanjikan; kurangi kebutuhan skill atau naikkan limit)"
                .to_string(),
        );
    }
    let tmp = std::env::temp_dir();
    let uniq = format!(
        "secai_ng_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let budget_path = tmp.join(format!("{uniq}.budget.json"));
    let audit_path = tmp.join(format!("{uniq}.audit.jsonl"));
    std::fs::write(
        &budget_path,
        json!({"limit": budget_limit, "used": 0}).to_string(),
    )
    .map_err(|e| format!("cannot write budget file: {e}"))?;

    // root repo (CARGO_MANIFEST_DIR = <root>/core-rs -> parent = <root>)
    // supaya sitecustomize bisa `from core.net_guard import ...`.
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        });
    let mut py_paths =
        vec![repo_root.clone(), repo_root.join("tools").join("net_guard")];
    if let Some(existing) = std::env::var_os("PYTHONPATH") {
        py_paths.push(PathBuf::from(existing));
    }
    let sep = if cfg!(windows) { ";" } else { ":" };
    let py_path = py_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(sep);
    let mut extra_env: Vec<(String, String)> = caller_env.to_vec();
    extra_env.extend([
        (GUARD_ENV.to_string(), "1".to_string()),
        (BUDGET_ENV.to_string(), budget_path.display().to_string()),
        (AUDIT_ENV.to_string(), audit_path.display().to_string()),
        ("PYTHONPATH".to_string(), py_path),
    ]);
    if let Some(scope) = scope_path {
        // Fase 2-C: scope-check + pin-IP anti-rebinding di sisi skill
        extra_env.push((SCOPE_ENV.to_string(), scope.display().to_string()));
    }

    let res = run_skill_with_env(skill_argv, out_path, workdir, &extra_env);

    // Verifikasi audit tidak boleh di-lewati meski skill sukses —
    // skill yang berjalan tanpa guard tidak bisa dinilai (fail-closed).
    let verify = verify_audit(&audit_path);
    let used_final = read_budget_used(&budget_path);
    let _ = std::fs::remove_file(&budget_path);

    let res = res?;
    let (total, allowed) = verify?;
    if let Some(used) = used_final {
        if used > budget_limit {
            return Err(format!(
                "net-guard: budget used {used} > limit {budget_limit} \
                 (kontrak rusak)"
            ));
        }
    }
    println!(
        "[net-guard] audit: {total} connection attempt(s), {allowed} \
         allowed, limit {budget_limit}"
    );
    Ok(res)
}

/// Verifikasi audit log net-guard (JSONL): file ADA, setiap baris JSON
/// valid dengan field kontrak, dan ada minimal satu baris
/// `kind="guard-install"`. Kembalikan (koneksi_tercatat, allowed).
pub fn verify_audit(path: &Path) -> Result<(usize, usize), String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|_| format!("net-guard audit log missing: {path:?}"))?;
    let mut total = 0usize;
    let mut allowed = 0usize;
    let mut installed = false;
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("audit line {} invalid: {e}", i + 1))?;
        for key in ["ts", "pid", "kind", "address", "allowed", "budget_used"] {
            if v.get(key).is_none() {
                return Err(format!("audit line {} missing '{key}'", i + 1));
            }
        }
        if v["allowed"].as_bool().is_none() {
            return Err(format!(
                "audit line {}: 'allowed' bukan boolean",
                i + 1
            ));
        }
        if v["kind"].as_str() == Some("guard-install") {
            installed = true;
        } else {
            total += 1;
            if v["allowed"].as_bool() == Some(true) {
                allowed += 1;
            }
        }
    }
    if !installed {
        return Err(
            "net-guard: tidak ada baris 'guard-install' — skill berjalan \
             tanpa guard (hard-fail)"
                .to_string(),
        );
    }
    Ok((total, allowed))
}

fn read_budget_used(path: &Path) -> Option<usize> {
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("used").and_then(|u| u.as_u64()).map(|u| u as usize)
}

/// Validasi file findings.json apa pun terhadap kontrak.
pub fn validate_file(path: &Path) -> Result<(usize, Vec<String>), String> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_FINDINGS_BYTES {
            return Err(format!(
                "findings.json too large >16MiB: {} bytes at {:?}",
                meta.len(),
                path
            ));
        }
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path:?}: {e}"))?;
    if (raw.len() as u64) > MAX_FINDINGS_BYTES {
        return Err(format!(
            "findings.json too large >16MiB: {} bytes at {:?}",
            raw.len(),
            path
        ));
    }
    let doc: FindingsDoc =
        serde_json::from_str(&raw).map_err(|e| format!("invalid findings.json: {e}"))?;
    let mut errs = Vec::new();
    for (i, f) in doc.findings.iter().enumerate() {
        if let Err(e) = f.validate() {
            errs.push(format!("findings[{i}] {}: {e}", f.title));
        }
    }
    Ok((doc.findings.len(), errs))
}

/// Tulis dokumen findings.json satu pintu (untuk merge hasil multi-skill).
pub fn write_merged(
    path: &Path,
    sources: &[String],
    findings: &[Finding],
    total_requests: u64,
    dedup_dropped: Option<usize>,
) -> Result<(), String> {
    let mut data = json!({
        "run": "secai-core",
        "sources": sources,
        "total_findings": findings.len(),
    });
    if let Some(n) = dedup_dropped {
        data["dedup"] = json!({ "duplicates_dropped": n });
    }
    let doc = json!({
        "ok": true,
        "data": data,
        "findings": findings,
        "requests": total_requests,
    });
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        path,
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{finding_id, verdict_tag};

    fn make_finding_json(tool: &str, title: &str, verdict: i8, target: &str) -> serde_json::Value {
        // buat baris dengan id/tag benar sesuai kontrak python
        let tag = verdict_tag(verdict);
        let id = finding_id(tool, title, Some(target), None, None);
        json!({
            "tool": tool, "title": title, "severity": "low",
            "description": "d", "target_url": target,
            "evidence_kind": "dns", "finding_class": "posture",
            "confidence": 1.0, "status": "confirmed",
            "verdict": verdict, "verdict_tag": tag, "id": id,
            "reportable": verdict >= 3,
        })
    }

    #[test]
    fn verdict_tags_match_python() {
        assert_eq!(verdict_tag(-1), "L-x REJECTED");
        assert_eq!(verdict_tag(0), "L0 OBSERVED - LEAD");
        assert_eq!(verdict_tag(1), "L1 SUSPECTED - LEAD");
        assert_eq!(verdict_tag(2), "L2 REPRODUCED - LEAD");
        assert_eq!(verdict_tag(3), "L3 DETERMINISTICALLY VERIFIED");
        assert_eq!(verdict_tag(4), "L4 IMPACT VERIFIED");
        assert_eq!(verdict_tag(5), "L5 BLIND VALIDATED");
    }

    #[test]
    fn write_merged_records_dedup_metadata() {
        // merge lintas-mode: data.dedup hanya muncul saat dedup aktif
        let tmp = std::env::temp_dir().join(format!("secai_wm_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let f = make_finding_json("t", "x", 1, "e.id");
        let finding: Finding = serde_json::from_value(f).unwrap();
        let out_with = tmp.join("with.json");
        write_merged(&out_with, &["a.json".into()], &[finding.clone()], 0, Some(3))
            .expect("write with dedup");
        let doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&out_with).unwrap(),
        )
        .unwrap();
        assert_eq!(doc["data"]["dedup"]["duplicates_dropped"], serde_json::json!(3));
        assert_eq!(doc["data"]["total_findings"], serde_json::json!(1));
        let out_plain = tmp.join("plain.json");
        write_merged(&out_plain, &["a.json".into()], &[finding], 0, None)
            .expect("write without dedup");
        let doc2: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&out_plain).unwrap(),
        )
        .unwrap();
        assert!(doc2["data"].get("dedup").is_none(), "tanpa dedup: tanpa metadata");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn id_matches_python_sha256_16() {
        // Nilai ekspektasi dihitung python (kontrak core/findings.py):
        //   sha256(b"t|x|example.id||")[:16]  => 660699c3c1db8a6f
        //   sha256(b"email-sender-surface|SPF soft-fail (~all) on example.go.id|example.go.id||")[:16]
        //     => b9ef722b963affb2
        assert_eq!(
            finding_id("t", "x", Some("example.id"), None, None),
            "660699c3c1db8a6f"
        );
        assert_eq!(
            finding_id(
                "email-sender-surface",
                "SPF soft-fail (~all) on example.go.id",
                Some("example.go.id"),
                None,
                None
            ),
            "b9ef722b963affb2"
        );
    }

    #[test]
    fn finding_validation_catches_severity() {
        let v = make_finding_json("t", "x", 1, "e.id");
        let mut f: Finding = serde_json::from_value(v).unwrap();
        f.severity = "catastrophic".into();
        assert!(f.validate().is_err());
    }

    #[test]
    fn finding_validation_catches_tag_and_id() {
        let v = make_finding_json("t", "x", 1, "e.id");
        let mut f: Finding = serde_json::from_value(v).unwrap();
        f.verdict_tag = "L9 WHATEVER".into();
        assert!(f.validate().is_err());
        let v2 = make_finding_json("t", "x", 1, "e.id");
        let mut f2: Finding = serde_json::from_value(v2).unwrap();
        f2.id = "0000000000000000".into();
        assert!(f2.validate().is_err());
    }

    #[test]
    fn extra_fields_survive_roundtrip() {
        let mut v = make_finding_json("t", "x", 1, "e.id");
        v["category"] = json!("AMAN");
        v["safety_class"] = json!("read-only");
        let f: Finding = serde_json::from_value(v.clone()).unwrap();
        assert!(f.validate().is_ok());
        let back = serde_json::to_value(&f).unwrap();
        assert_eq!(back["category"], json!("AMAN"));
        assert_eq!(back["safety_class"], json!("read-only"));
    }

    #[test]
    fn runner_executes_python_subprocess_and_validates() {
        // Simulasi skill python: tulis findings.json valid via placeholder @OUT@
        let tmp = std::env::temp_dir().join(format!("secai_test_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = tmp.join("out.json");
        let script = r#"
import json, sys, hashlib
def vid(tool,title,target,verdict,tag):
    h=hashlib.sha256(f"{tool}|{title}|{target}||".encode()).hexdigest()[:16]
    return {"tool":tool,"title":title,"severity":"low","description":"d",
            "target_url":target,"evidence_kind":"dns","finding_class":"posture",
            "confidence":1.0,"status":"confirmed","verdict":verdict,
            "verdict_tag":tag,"id":h,"reportable":verdict>=3}
rows=[vid("t","ok-lead","x.id",1,"L1 SUSPECTED - LEAD"),
      vid("t","ok-obs","x.id",0,"L0 OBSERVED - LEAD")]
open(sys.argv[1],"w").write(json.dumps({"ok":True,"data":{"k":1},"findings":rows,"requests":0}))
"#;
        let argv = vec![
            "python".to_string(),
            "-c".to_string(),
            script.to_string(),
            "@OUT@".to_string(),
        ];
        let res = run_skill(&argv, &out, None).expect("run should succeed");
        assert!(res.ok, "invalid: {:?}", res.invalid);
        assert_eq!(res.findings, 2);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn runner_fails_hard_on_bad_contract_output() {
        let tmp = std::env::temp_dir().join(format!("secai_testbad_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = tmp.join("out.json");
        let script = r#"
import json, sys
rows=[{"tool":"t","title":"broken","severity":"gila","verdict":1,
       "verdict_tag":"WRONG","id":"00","reportable":True}]
open(sys.argv[1],"w").write(json.dumps({"ok":True,"data":{},"findings":rows}))
"#;
        let argv = vec!["python".to_string(), "-c".to_string(), script.to_string(), "@OUT@".to_string()];
        let res = run_skill(&argv, &out, None).expect("run should execute");
        assert!(!res.ok, "harus gagal validasi kontrak");
        assert!(!res.invalid.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- net-guard Fase 2-B lanjutan (run_skill_guarded / verify_audit) ----

    fn audit_row(kind: &str, allowed: bool) -> String {
        serde_json::json!({"ts": 1.0, "pid": 1, "kind": kind,
            "address": "127.0.0.1:9", "allowed": allowed,
            "budget_used": 1})
        .to_string()
    }

    #[test]
    fn verify_audit_ok_counts_connections() {
        let p = std::env::temp_dir()
            .join(format!("secai_t_va_{}.jsonl", std::process::id()));
        std::fs::write(
            &p,
            format!(
                "{}\n{}\n{}\n",
                audit_row("guard-install", true),
                audit_row("tcp-connect", true),
                audit_row("tcp-connect", false)
            ),
        )
        .unwrap();
        let r = verify_audit(&p).expect("verify should pass");
        assert_eq!(r, (2, 1));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn verify_audit_missing_is_hard_fail() {
        let p = std::env::temp_dir()
            .join(format!("secai_t_vm_{}.jsonl", std::process::id()));
        let err = verify_audit(&p).unwrap_err();
        assert!(err.contains("missing"), "err={err}");
    }

    #[test]
    fn verify_audit_corrupt_line_is_hard_fail() {
        let p = std::env::temp_dir()
            .join(format!("secai_t_vc_{}.jsonl", std::process::id()));
        std::fs::write(
            &p,
            format!("{}\nbukan-json\n", audit_row("guard-install", true)),
        )
        .unwrap();
        let err = verify_audit(&p).unwrap_err();
        assert!(err.contains("invalid"), "err={err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn verify_audit_without_install_marker_is_hard_fail() {
        let p = std::env::temp_dir()
            .join(format!("secai_t_vn_{}.jsonl", std::process::id()));
        std::fs::write(&p, format!("{}\n", audit_row("tcp-connect", true)))
            .unwrap();
        let err = verify_audit(&p).unwrap_err();
        assert!(err.contains("guard-install"), "err={err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn guarded_run_records_connections_with_budget() {
        // e2e: dua attempt ke 127.0.0.1:9 dengan budget 1 -> 1 allowed,
        // 1 ditolak SEBELUM connect; marker guard-install ada.
        let script = r#"
import socket, json, sys
for _ in range(2):
    try:
        s = socket.create_connection(("127.0.0.1", 9), timeout=1)
        s.close()
    except OSError:
        pass
json.dump({"ok": True, "findings": []},
          open(sys.argv[1], "w", encoding="utf-8"))
"#;
        let argv = vec![
            "python".to_string(),
            "-c".to_string(),
            script.to_string(),
            "@OUT@".to_string(),
        ];
        let out = std::env::temp_dir()
            .join(format!("secai_t_guard_{}.json", std::process::id()));
        let res = run_skill_guarded(&argv, &out, None, 1, None, &[])
            .expect("guarded run should pass");
        assert!(res.ok, "invalid: {:?}", res.invalid);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn guarded_run_hard_fails_when_skill_removes_audit() {
        // Skill yang menghapus audit log = berjalan tanpa bukti guard
        // -> runner hard-fail (fail-closed dua lapis).
        let script = r#"
import os, json, sys
json.dump({"ok": True, "findings": []},
          open(sys.argv[1], "w", encoding="utf-8"))
try:
    os.remove(os.environ["SECAI_NET_AUDIT"])
except Exception:
    pass
"#;
        let argv = vec![
            "python".to_string(),
            "-c".to_string(),
            script.to_string(),
            "@OUT@".to_string(),
        ];
        let out = std::env::temp_dir()
            .join(format!("secai_t_guard2_{}.json", std::process::id()));
        let err = run_skill_guarded(&argv, &out, None, 3, None, &[]).unwrap_err();
        assert!(err.contains("missing"), "err={err}");
    }

    #[test]
    fn guarded_run_with_scope_passes_through_and_audits_deny() {
        // Fase 2-C: scope file (127.0.0.1 DI LUAR scope) -> kedua attempt
        // ter-scope-deny; skill tetap exit 0 (menangkap OSError); audit
        // memuat baris scope-deny dan guard-install tetap ada.
        let script = r#"
import socket, json, sys
denied = 0
for _ in range(2):
    try:
        s = socket.create_connection(("127.0.0.1", 9), timeout=1)
        s.close()
    except OSError:
        denied += 1
json.dump({"ok": True, "findings": [],
           "note": f"denied={denied}"},
          open(sys.argv[1], "w", encoding="utf-8"))
"#;
        let scope = std::env::temp_dir()
            .join(format!("secai_t_scope_{}.json", std::process::id()));
        std::fs::write(
            &scope,
            json!({"domains": ["unrelated.test"], "ips": [], "cidrs": []})
                .to_string(),
        )
        .unwrap();
        let argv = vec![
            "python".to_string(),
            "-c".to_string(),
            script.to_string(),
            "@OUT@".to_string(),
        ];
        let out = std::env::temp_dir()
            .join(format!("secai_t_scoped_{}.json", std::process::id()));
        let res = run_skill_guarded(
            &argv, &out, None, 5, Some(scope.as_path()), &[],
        )
        .expect("guarded run with scope should pass");
        assert!(res.ok, "invalid: {:?}", res.invalid);
        let _ = std::fs::remove_file(&out);
        let _ = std::fs::remove_file(&scope);
    }

    #[test]
    fn guarded_run_rejects_zero_budget_before_spawn() {
        let argv = vec!["python".to_string(), "-c".to_string(),
                        "pass".to_string()];
        let out = std::env::temp_dir()
            .join(format!("secai_t_guard3_{}.json", std::process::id()));
        let err = run_skill_guarded(&argv, &out, None, 0, None, &[]).unwrap_err();
        assert!(err.contains("budget 0"), "err={err}");
    }
}
