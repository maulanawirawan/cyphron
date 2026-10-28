//! F4 — Worker skeleton: konsumsi job dari queue (NATS JetStream),
//! jalankan skill via runner (kontrak findings.json), fail-closed.
//!
//! Shape job (JSON pada pesan):
//!   {"cmd": ["python", "skills/x.py", "--domain", "d", "--out", "@OUT@"],
//!    "out": "findings/run-1/x.json"}
//! `@OUT@` diganti path absolut output (sama seperti `cyphron run`).
//!
//! Kebijakan ack:
//!   - sukses + kontrak valid  -> ACK
//!   - skill exit non-zero     -> NAK (redelivery — diasumsikan transien)
//!   - kontrak dilanggar       -> ACK-TERM + log ke file error (anti
//!     poison-loop; job tidak hilang senyap — jejaknya tertulis)
use crate::runner::run_skill;
use futures_util::StreamExt;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Job {
    pub cmd: Vec<String>,
    pub out: String,
    #[serde(default)]
    pub job_id: Option<String>,
}

pub enum JobOutcome {
    Ack,
    Nak(String),
    Term(String),
}

const MAX_DELIVER: u64 = 3;

/// Jalankan satu job tanpa mengetahui queue-nya (testable).
pub fn run_job(job: &Job, workdir: &Path) -> JobOutcome {
    if job.cmd.is_empty() || job.out.is_empty() {
        return JobOutcome::Term("job tanpa cmd/out".into());
    }
    let out_path = PathBuf::from(&job.out);
    // guard: out must stay under workdir
    let workdir_canon = std::fs::canonicalize(workdir).unwrap_or_else(|_| workdir.to_path_buf());
    let out_canon_parent = if out_path.is_absolute() {
        out_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("/"))
    } else {
        workdir_canon.join(out_path.parent().unwrap_or(Path::new(".")))
    };
    // simple check: reject if out contains ".." or is absolute outside workdir
    if job.out.contains("..") || (out_path.is_absolute() && !out_path.starts_with(&workdir_canon)) {
        return JobOutcome::Term("out path escapes workdir (traversal blocked)".into());
    }
    let _ = &out_canon_parent;
    match run_skill(&job.cmd, &out_path, Some(workdir)) {
        Ok(res) if res.ok => JobOutcome::Ack,
        Ok(res) => JobOutcome::Term(format!(
            "kontrak dilanggar ({} temuan, {} invalid): {}",
            res.findings,
            res.invalid.len(),
            res.invalid.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
        )),
        Err(e) => JobOutcome::Nak(e),
    }
}

/// Loop worker: konek NATS, durable pull consumer, proses job satu-satu.
pub async fn worker_loop(
    url: &str,
    subject: &str,
    workdir: &Path,
    error_log: &Path,
) -> Result<(), String> {
    let client = async_nats::connect(url)
        .await
        .map_err(|e| format!("connect {url}: {e}"))?;
    let js = async_nats::jetstream::new(client);
    let stream_name = subject.split('.').next().unwrap_or("scans").to_uppercase();
    // stream + durable dibuat idempoten
    let stream = js
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: stream_name.clone(),
            subjects: vec![subject.to_string()],
            ..Default::default()
        })
        .await
        .map_err(|e| format!("stream: {e}"))?;
    let consumer = stream
        .get_or_create_consumer(
            &stream_name.to_lowercase(),
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(stream_name.to_lowercase()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| format!("consumer: {e}"))?;

    println!("worker: terhubung {url}, subject {subject}, workdir {}",
             workdir.display());
    loop {
        let batch = consumer
            .batch()
            .max_messages(1)
            .expires(std::time::Duration::from_secs(2))
            .messages()
            .await
            .map_err(|e| format!("fetch: {e}"))?;
        let mut batch = std::pin::pin!(batch);
        while let Some(Ok(msg)) = batch.next().await {
            if msg.payload.len() > 64 * 1024 {
                let reason = format!("payload too large {} bytes >64KiB", msg.payload.len());
                log_error(error_log, "unknown", &msg.payload.len().to_string(), &reason, 1);
                let _ = msg.ack_with(async_nats::jetstream::AckKind::Term).await;
                eprintln!("  TERM: {reason}");
                continue;
            }
            let (outcome, job_id_owned, job_out_owned) = match serde_json::from_slice::<Job>(&msg.payload) {
                Ok(job) => {
                    println!("job {} -> {} ({} arg)",
                             job.job_id.clone().unwrap_or_default(),
                             job.out,
                             job.cmd.len());
                    let jid = job.job_id.clone().unwrap_or_default();
                    let out = job.out.clone();
                    let o = run_job(&job, workdir);
                    (o, jid, out)
                }
                Err(e) => (JobOutcome::Term(format!("payload bukan job: {e}")), String::new(), String::new()),
            };
            match outcome {
                JobOutcome::Ack => {
                    let _ = msg.ack().await;
                    println!("  ACK");
                }
                JobOutcome::Nak(reason) => {
                    let delivered = msg
                        .info()
                        .map(|i| i.delivered.max(1) as u64)
                        .unwrap_or(1);
                    if delivered >= MAX_DELIVER {
                        let _ = msg.ack_with(async_nats::jetstream::AckKind::Term).await;
                        let reason = format!(
                            "max redelivery ({MAX_DELIVER}) tercapai: {reason}"
                        );
                        eprintln!("  TERM: {reason}");
                        log_error(error_log, &job_id_owned, &job_out_owned, &reason, delivered);
                    } else {
                        let base = 2u64.saturating_pow(delivered.min(6) as u32).min(60);
                        let jitter_ms = (delivered * 211) % 1000;
                        let delay = std::time::Duration::from_millis(base * 1000 + jitter_ms);
                        let _ = msg
                            .ack_with(async_nats::jetstream::AckKind::Nak(Some(delay)))
                            .await;
                        eprintln!("  NAK ({}x): {reason}", delivered);
                    }
                }
                JobOutcome::Term(reason) => {
                    let delivered = msg
                        .info()
                        .map(|i| i.delivered.max(1) as u64)
                        .unwrap_or(1);
                    let _ = msg.ack_with(async_nats::jetstream::AckKind::Term).await;
                    eprintln!("  TERM: {reason}");
                    log_error(error_log, &job_id_owned, &job_out_owned, &reason, delivered);
                }
            }
        }
    }
}

fn log_error(error_log: &Path, job_id: &str, out: &str, reason: &str, delivered: u64) {
    use std::io::Write;
    if let Some(parent) = error_log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(error_log)
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let entry = serde_json::json!({
            "ts_epoch": now,
            "job_id": job_id,
            "out": out,
            "reason": reason,
            "delivered": delivered
        });
        let _ = writeln!(f, "{entry}");
    }
}

fn chrono_like_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch={now}")
}
