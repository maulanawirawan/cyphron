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
/// CYPHRON_UA untuk profil User-Agent, HTTP(S)_PROXY untuk proxy run).
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
        "run": "cyphron-core",
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
        let tmp = std::env::temp_dir().join(format!("cyphron_wm_{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("cyphron_test_{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("cyphron_testbad_{}", std::process::id()));
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
}
