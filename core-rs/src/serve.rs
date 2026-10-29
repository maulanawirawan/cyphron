//! F5 — Dashboard skeleton: HTTP server std-only (tanpa dependency),
//! read-only, bind 127.0.0.1. Menyajikan:
//!   GET /                -> dashboard statis (vanilla JS)
//!   GET /api/runs        -> daftar findings.json di bawah --dir
//!   GET /api/run?path=R  -> isi findings.json (hanya di bawah --dir)
//!   GET /report?path=R   -> PDF laporan (hanya di bawah --dir)
//!
//! Skeleton tanpa build step; React+Vite masuk saat fitur UI nyata
//! (keputusan F1 tetap: budget bundle ketat, tanpa three/gsap).

use crate::contract::FindingsDoc;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

static RATE_LIMIT: OnceLock<Mutex<HashMap<String, VecDeque<Instant>>>> = OnceLock::new();

fn check_rate_limit(ip: &str) -> bool {
    let map = RATE_LIMIT.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = map.lock().unwrap();
    let now = Instant::now();
    let entry = g.entry(ip.to_string()).or_insert_with(VecDeque::new);
    while entry.front().map(|t| now.duration_since(*t) > Duration::from_secs(60)).unwrap_or(false) { entry.pop_front(); }
    if entry.len() >= 60 { return false; }
    entry.push_back(now);
    true
}

/// F11 — auth multi-operator dari nol: token -> {operator, role}.
/// Role: "admin" (semua akses) / "viewer" (baca — semua endpoint saat ini
/// read-only). Tanpa auth map = mode lokal terbuka (bind 127.0.0.1).
#[derive(Clone, Debug)]
pub struct Auth {
    pub map: HashMap<String, (String, String)>, // token -> (operator, role)
}

impl Auth {
    pub fn from_single(token: &str) -> Self {
        let mut map = HashMap::new();
        map.insert(
            token.to_string(),
            ("single-token".to_string(), "admin".to_string()),
        );
        Auth { map }
    }

    pub fn from_file(path: &Path) -> Result<Auth, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("auth file {path:?}: {e}"))?;
        let doc: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let mut map = HashMap::new();
        let mut seen = HashSet::new();
        for t in doc
            .get("tokens")
            .and_then(|v| v.as_array())
            .ok_or("auth file tanpa 'tokens' array")?
        {
            let token = t
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or("entry tanpa 'token'")?;
            if token.trim().is_empty() {
                return Err("empty token".into());
            }
            if seen.contains(token) {
                return Err(format!("duplicate token: {}", token));
            }
            seen.insert(token.to_string());
            let operator = t
                .get("operator")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let role = t
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("viewer");
            map.insert(token.to_string(), (operator.to_string(), role.to_string()));
        }
        if map.is_empty() {
            return Err("auth file kosong — fail-closed".into());
        }
        Ok(Auth { map })
    }
}

/// Redaksi kredensial di query string SEBELUM masuk audit log (audit
/// 2026-10: token via ?token= tercatat apa adanya). Redaksi diterapkan
/// di sink — satu titik menutup semua pemanggil, termasuk jalur 401.
fn redact_credentials(target: &str) -> String {
    let Some((path, query)) = target.split_once('?') else {
        return target.to_string();
    };
    let redacted: Vec<String> = query
        .split('&')
        .map(|kv| {
            if kv.split_once('=').map(|(k, _)| k == "token").unwrap_or(false) {
                "token=[REDACTED]".to_string()
            } else {
                kv.to_string()
            }
        })
        .collect();
    format!("{path}?{}", redacted.join("&"))
}

/// Audit log: JSONL append — setiap request tercatat (ts, ip, operator,
/// path, status). Rantai jejak untuk enterprise. Kredensial di-redaksi
/// sebelum ditulis (token tidak pernah masuk log).
fn audit_write(path: Option<&Path>, ip: &str, method: &str, target: &str,
               status: &str, operator: &str) {
    let target = redact_credentials(target);
    let target = target.as_str();
    let Some(p) = path else { return };
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p)
    {
        use std::io::Write as _;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(
            f,
            "{}",
            serde_json::json!({
                "ts_epoch": ts, "ip": ip, "method": method,
                "path": target, "status": status, "operator": operator,
            })
        );
    }
}

pub struct RunEntry {
    pub rel: String,
    pub ok: bool,
    pub total: usize,
    pub reportable: usize,
    pub requests: u32,
}

/// Daftar semua findings.json di bawah dir (rekursif), tervalidasi ringan.
pub fn list_runs(dir: &Path) -> Vec<RunEntry> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().map(|f| f == "findings.json").unwrap_or(false) {
                let rel = p
                    .strip_prefix(dir)
                    .map(|r| r.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                if let Ok(raw) = std::fs::read_to_string(&p) {
                    if let Ok(doc) = serde_json::from_str::<FindingsDoc>(&raw) {
                        let reportable =
                            doc.findings.iter().filter(|f| f.reportable).count();
                        out.push(RunEntry {
                            rel,
                            ok: doc.ok,
                            total: doc.findings.len(),
                            reportable,
                            requests: doc.requests,
                        });
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    out
}

/// Guard traversal: path relatif HARUS tetap di dalam dir.
pub fn resolve_under(dir: &Path, rel: &str) -> Option<PathBuf> {
    if rel.contains("..") || rel.contains("\\") || rel.contains(':') || rel.contains('\0') || rel.starts_with('/') || rel.starts_with('\\') {
        return None;
    }
    // percent-decode loop for %2e %2f %5c
    let mut decoded = rel.to_string();
    for _ in 0..3 {
        let lower = decoded.to_lowercase();
        if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
            decoded = decoded.replace("%2e", ".").replace("%2E", ".").replace("%2f", "/").replace("%2F", "/").replace("%5c", "\\").replace("%5C", "\\");
        } else { break; }
    }
    if decoded.contains("..") || decoded.contains("\\") || decoded.contains(':') || decoded.contains('\0') || decoded.starts_with('/') || decoded.starts_with('\\') {
        return None;
    }
    let p = dir.join(&decoded);
    let canon = std::fs::canonicalize(&p).ok()?;
    let base = std::fs::canonicalize(dir).ok()?;
    if canon.starts_with(&base) { Some(canon) } else { None }
}

/// Audit 2026-10: JS + CSS dashboard pindah ke aset eksternal yang disaji-
/// kan server sendiri — CSP `script-src 'self'` tidak memblokir dashboard
/// sendiri lagi (dulu inline script diblokir `default-src 'none'`).
const DASHBOARD_CSS: &str = include_str!("assets/dashboard.css");
const DASHBOARD_JS: &str = include_str!("assets/dashboard.js");

const DASHBOARD: &str = r#"<!doctype html><html lang="id"><head><meta charset="utf-8">
<title>Cyphron — Dashboard</title>
<link rel="stylesheet" href="/assets/dashboard.css">
</head><body>
<h1>Cyphron <small>(working title)</small> — Dashboard</h1>
<small>Baca findings.json satu pintu · LOCAL-ONLY · bind 127.0.0.1</small>
<table id="t"><thead><tr><th>Run</th><th>Temuan</th><th>Reportable L3+</th><th>Request</th><th>Laporan</th></tr></thead><tbody></tbody></table>
<script src="/assets/dashboard.js"></script>
</body></html>"#;

fn http_response(status: &str, ctype: &str, body: Vec<u8>) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend(body);
    out
}

fn handle(mut stream: TcpStream, dir: &Path) {
    handle_with_token(stream, dir, None, None)
}

fn handle_with_token(mut stream: TcpStream, dir: &Path,
                     auth: Option<&Auth>, audit_path: Option<&Path>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    let mut lines = req.lines();
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    let qpath = query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == "path").then(|| v.to_string())
    });
    let qtoken = query
        .split('&')
        .find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == "token").map(|(_, v)| v.to_string()));
    let header_token = req
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .and_then(|l| l.split_once(' '))
        .map(|(_, v)| v.trim().to_string());

    // F11: kalau auth map disetel, token wajib dikenal; operator+role
    // tercatat di audit log. Role viewer = baca (semua endpoint saat ini
    // read-only); role lain/unknown = 403.
    let mut operator = "anonymous".to_string();
    let ip = if peer.starts_with('[') {
        peer.split(']').next().unwrap_or(&peer).trim_start_matches('[').to_string()
    } else {
        // IPv4: 127.0.0.1:port -> take before colon; handle no colon
        match peer.rfind(':') {
            Some(idx) if peer[idx..].chars().filter(|c| *c == ':').count() == 1 => peer[..idx].to_string(),
            Some(_) => peer.split(':').next().unwrap_or(&peer).to_string(),
            None => peer.clone(),
        }
    };
    if !check_rate_limit(&ip) {
        let body = b"rate limit 60/min".to_vec();
        let resp = format!(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'\r\nReferrer-Policy: no-referrer\r\nRetry-After: 60\r\nConnection: close\r\n\r\n",
            body.len()
        ).into_bytes().into_iter().chain(body).collect::<Vec<u8>>();
        let _ = stream.write_all(&resp);
        audit_write(audit_path, &peer, method, target, "429", &operator);
        return;
    }
    if let Some(auth) = auth {
        let supplied = qtoken.as_deref().or(header_token.as_deref());
        match supplied.and_then(|t| auth.map.get(t)) {
            Some((op, role)) => {
                operator = op.clone();
                if role != "admin" && role != "viewer" {
                    let _ = stream.write_all(&http_response(
                        "403 Forbidden", "text/plain; charset=utf-8",
                        b"role tidak dikenal".to_vec(),
                    ));
                    audit_write(audit_path, &peer, method, target,
                                "403", &operator);
                    return;
                }
            }
            None => {
                let _ = stream.write_all(&http_response(
                    "401 Unauthorized", "text/plain; charset=utf-8",
                    b"token tidak valid".to_vec(),
                ));
                audit_write(audit_path, &peer, method, target, "401", "invalid-token");
                return;
            }
        }
    }

    let resp = match (path, qpath) {
        ("/", _) => http_response("200 OK", "text/html; charset=utf-8",
                                  DASHBOARD.as_bytes().to_vec()),
        ("/assets/dashboard.css", _) => http_response(
            "200 OK", "text/css; charset=utf-8",
            DASHBOARD_CSS.as_bytes().to_vec(),
        ),
        ("/assets/dashboard.js", _) => http_response(
            "200 OK", "text/javascript; charset=utf-8",
            DASHBOARD_JS.as_bytes().to_vec(),
        ),
        ("/api/runs", _) => {
            let runs: Vec<serde_json::Value> = list_runs(dir)
                .iter()
                .map(|r| {
                    let pdf = PathBuf::from(&r.rel)
                        .parent()
                        .map(|p| p.join("report.pdf"))
                        .filter(|p| dir.join(p).exists())
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_default();
                    serde_json::json!({
                        "rel": r.rel, "ok": r.ok, "total": r.total,
                        "reportable": r.reportable, "requests": r.requests,
                        "pdf": pdf,
                    })
                })
                .collect();
            http_response("200 OK", "application/json",
                          serde_json::to_vec(&runs).unwrap_or_default())
        }
        ("/api/run", Some(rel)) => match resolve_under(dir, &rel) {
            Some(p) if p.file_name().map(|f| f == "findings.json").unwrap_or(false) => {
                match std::fs::read(&p) {
                    Ok(b) => http_response("200 OK", "application/json", b),
                    Err(e) => http_response("500 Internal Server Error",
                                            "text/plain", e.to_string().into_bytes()),
                }
            }
            _ => http_response("403 Forbidden", "text/plain",
                               b"path di luar dir / bukan findings.json".to_vec()),
        },
        ("/report", Some(rel)) => match resolve_under(dir, &rel) {
            Some(p) if p.extension().map(|e| e == "pdf").unwrap_or(false) => {
                match std::fs::read(&p) {
                    Ok(b) => http_response("200 OK", "application/pdf", b),
                    Err(e) => http_response("500 Internal Server Error",
                                            "text/plain", e.to_string().into_bytes()),
                }
            }
            _ => http_response("403 Forbidden", "text/plain",
                               b"path di luar dir / bukan PDF".to_vec()),
        },
        _ => http_response("404 Not Found", "text/plain", b"not found".to_vec()),
    };
    let status = resp[9..12].to_vec();
    let status_str = String::from_utf8_lossy(&status).to_string();
    audit_write(audit_path, &peer, method, target, &status_str, &operator);
    let _ = stream.write_all(&resp);
}

/// Loop server (blocking, thread per koneksi) — dipanggil dari main.
pub fn serve_loop(dir: &Path, port: u16, auth: Option<Auth>,
                  audit_path: Option<PathBuf>) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("bind 127.0.0.1:{port}: {e}"))?;
    match &auth {
        Some(_) => println!("serve: http://127.0.0.1:{port}/ (dir {}, auth: multi-operator aktif)", dir.display()),
        None => println!("serve: http://127.0.0.1:{port}/ (dir {}, auth: terbuka-lokal)", dir.display()),
    }
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let d = dir.to_path_buf();
                let a = auth.clone();
                let ap = audit_path.clone();
                std::thread::spawn(move || {
                    handle_with_token(s, &d, a.as_ref(), ap.as_deref())
                });
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn audit_log_never_contains_token() {
        // audit 2026-10: token via ?token= tidak boleh masuk audit log
        let tmp = std::env::temp_dir().join(format!("cyphron_audit_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("audit.jsonl");
        audit_write(Some(&p), "127.0.0.1:1", "GET",
                    "/api/runs?token=rahasia123&x=1", "200", "owner");
        audit_write(Some(&p), "127.0.0.1:2", "GET",
                    "/api/run?token=rahasia123", "401", "invalid-token");
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(!content.contains("rahasia123"), "token bocor ke log: {content}");
        assert!(content.contains("token=%5BREDACTED%5D") || content.contains("token=[REDACTED]"),
                "redaksi harus tercatat eksplisit: {content}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn dashboard_serves_external_assets_not_inline_js() {
        // CSP script-src 'self' + aset eksternal: markup dashboard tanpa
        // inline script; aset disaji sendiri di /assets/*
        assert!(!DASHBOARD.contains("<script>"), "inline script masih ada");
        assert!(DASHBOARD.contains("/assets/dashboard.js"));
        assert!(DASHBOARD_JS.contains("textContent"), "DOM harus via textContent");
        assert!(!DASHBOARD_JS.contains("innerHTML"), "innerHTML dilarang");
        assert!(http_response("200 OK", "application/json", b"{}".to_vec())
            .windows(b"script-src 'self'".len())
            .any(|w| w == b"script-src 'self'"),
            "CSP harus mengizinkan aset self");
    }

    #[test]
    fn auth_file_loads_tokens_and_rejects_empty() {
        let tmp = std::env::temp_dir().join(format!("cyphron_auth_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("tokens.json");
        std::fs::write(&p, serde_json::json!({"tokens": [
            {"token": "t-admin", "operator": "owner", "role": "admin"},
            {"token": "t-view", "operator": "auditor", "role": "viewer"}
        ]}).to_string()).unwrap();
        let auth = Auth::from_file(&p).unwrap();
        assert_eq!(auth.map.len(), 2);
        assert_eq!(auth.map["t-view"].0, "auditor");
        std::fs::write(&p, "{\"tokens\": []}").unwrap();
        assert!(Auth::from_file(&p).is_err(), "auth kosong harus fail-closed");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Tulis satu run fixture sintetis (deterministik, kontrak-parseable)
    /// ke pohon dir sementara — test tidak bergantung pada data lokal.
    fn write_fixture_run(dir: &Path, rel: &str, total: usize) {
        let rows: Vec<serde_json::Value> = (0..total)
            .map(|i| {
                serde_json::json!({
                    "tool": "t", "title": format!("row {i}"),
                    "severity": "low", "verdict": 0,
                    "verdict_tag": "L0 OBSERVED - LEAD",
                    "id": format!("{i:016x}"), "reportable": false,
                })
            })
            .collect();
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            serde_json::json!({
                "ok": true, "data": {}, "findings": rows, "requests": 0
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn list_runs_finds_findings_json() {
        let tmp =
            std::env::temp_dir().join(format!("cyphron_runs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        write_fixture_run(&tmp, "tier0-contoh/findings.json", 2);
        let runs = list_runs(&tmp);
        let t = runs
            .iter()
            .find(|r| r.rel == "tier0-contoh/findings.json")
            .expect("fixture harus terdeteksi");
        assert_eq!(t.total, 2);
        assert!(t.ok);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_under_blocks_traversal() {
        let tmp =
            std::env::temp_dir().join(format!("cyphron_res_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        write_fixture_run(&tmp, "tier0-contoh/findings.json", 1);
        // valid: file di dalam dir
        assert!(resolve_under(&tmp, "tier0-contoh/findings.json").is_some());
        // traversal klasik
        assert!(resolve_under(&tmp, "../core/findings.py").is_none());
        assert!(resolve_under(&tmp, "..\\core\\findings.py").is_none());
        // absolute path di luar dir
        assert!(resolve_under(&tmp, "C:/Windows/win.ini").is_none());
        // path yang tidak ada
        assert!(resolve_under(&tmp, "tidak/ada.json").is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn token_auth_rejects_without_and_allows_with() {
        // server ephemeral dengan Auth map; uji 401 tanpa token, 200 dengan
        let dir = PathBuf::from("../findings");
        let mut map = HashMap::new();
        map.insert(
            "rahasia123".to_string(),
            ("owner".to_string(), "admin".to_string()),
        );
        let auth = Auth { map };
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let d = dir.clone();
                let a = auth.clone();
                std::thread::spawn(move || handle_with_token(s, &d, Some(&a), None));
            }
        });
        // tanpa token -> 401
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"GET /api/runs HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        assert!(buf.starts_with("HTTP/1.1 401"), "tanpa token harus 401: {buf}");
        // token via query -> 200
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"GET /api/runs?token=rahasia123 HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        assert!(buf.starts_with("HTTP/1.1 200"), "token benar harus 200: {buf}");
        // token salah -> 401
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"GET /api/runs?token=salah HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        assert!(buf.starts_with("HTTP/1.1 401"), "token salah harus 401");
    }
}
