//! F8 — FAO (Findings-Augmented Orchestration): korelasi & integritas bukti.
//!
//! Aturan main (honest-by-design, tidak mengarang verdict):
//!   1. DEDUP: id identik (tool|title|target) = temuan sama, digabung.
//!   2. QUORUM: temuan dengan (target, category, cwe) sama dari >= 2 TOOL
//!      BERBEDA (sumber independen) diberi metadata quorum + sources.
//!   3. CROSS-CONFIRM: hanya lead L1 yang naik ke L2 (REPRODUCED oleh
//!      sumber kedua). L0 tidak pernah naik (inventaris bukan kerentanan);
//!      L3+ tidak disentuh (sudah reportable). Kenaikan diberi catatan
//!      eksplisit di description.
//!   4. FAMILY QUORUM (F18): temuan keluarga header pada (target, header)
//!      sama dari >= 3 TOOL berbeda (lintas aspek/kunci) diberi metadata
//!      family_quorum + family_sources — TANPA kenaikan verdict (zero-FP:
//!      kenaikan kelas tetap eksklusif quorum kunci identik).
//!   5. EVIDENCE HASH: sha256(request|response|poc) per temuan — rantai
//!      bukti yang bisa diverifikasi, bukan klaim lepas.

use crate::contract::Finding;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

fn hex_full(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// sha256(request|response|poc)[:16] — bukti mentah dari extra (field
/// request/response/poc hidup di extra karena kontrak python menyuntiknya
/// sebagai extension).
pub fn evidence_hash(f: &Finding) -> String {
    let norm = |k: &str| {
        let s = f
            .extra
            .get(k)
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let basis = format!("{}|{}|{}", norm("request"), norm("response"), norm("poc"));
    // Audit 2026-10: dulu dipotong 16 hex — integritas jangka panjang
    // pakai digest SHA-256 penuh (64 hex).
    hex_full(&Sha256::digest(basis.as_bytes()))
}

fn key_of(f: &Finding) -> String {
    let cat = f
        .extra
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    format!(
        "{}|{}|{}",
        f.target_url.clone().unwrap_or_default(),
        cat,
        f.cwe.clone().unwrap_or_default()
    )
}

/// Kunci keluarga header: (target, "header-family", nama_header) — hanya
/// temuan yang menandai extra.header eksplisit (zero-FP: tanpa tag yang
/// bisa dipercaya, temuan tidak masuk keluarga).
fn header_family_key(f: &Finding) -> Option<String> {
    let header = f.extra.get("header")?.as_str()?;
    if header.trim().is_empty() {
        return None;
    }
    Some(format!(
        "{}|header-family|{}",
        f.target_url.clone().unwrap_or_default(),
        header.to_lowercase()
    ))
}

/// Dedup by id (tool|title|target|file|param): baris pertama dipertahankan,
/// duplikat dibuang, `dup_count` di baris pertama mencatat total kemunculan.
/// Return jumlah baris yang dibuang. Dipakai FAO (per-run) DAN
/// `cyphron merge --dedup-id` (penggabungan lintas-mode tier0/lab) — satu
/// semantik untuk semua jalur, sama seperti tools/merge_findings.py.
pub fn dedup_by_id(findings: &mut Vec<Finding>) -> usize {
    let mut idx_by_id: HashMap<String, usize> = HashMap::new();
    let mut deduped: Vec<Finding> = Vec::new();
    let mut dropped = 0usize;
    for f in findings.drain(..) {
        match idx_by_id.get(&f.id) {
            Some(&i) => {
                dropped += 1;
                let e = deduped[i]
                    .extra
                    .entry("dup_count".to_string())
                    .or_insert(serde_json::json!(1));
                if let Some(n) = e.as_u64() {
                    let next = if n == u64::MAX { n } else { n + 1 };
                    *e = serde_json::json!(next);
                }
            }
            None => {
                idx_by_id.insert(f.id.clone(), deduped.len());
                deduped.push(f);
            }
        }
    }
    *findings = deduped;
    dropped
}

/// Korelasi penuh: dedup -> quorum -> cross-confirm -> evidence hash.
pub fn correlate(findings: &mut Vec<Finding>) {
    // --- 1. dedup by id (helper bersama dengan merge lintas-mode)
    dedup_by_id(findings);
    let mut deduped: Vec<Finding> = std::mem::take(findings);

    deduped.sort_by(|a, b| a.id.cmp(&b.id));

    // --- 2. quorum per kunci (target|category|cwe), butuh >= 2 tool unik
    // zero-FP: hanya baris status "confirmed" yang boleh saling
    // mengonfirmasi — dua tool yang GAGAL dengan cara sama (DNS timeout,
    // dll.) bukan konfirmasi silang, itu kebetulan lingkungan.
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, f) in deduped.iter().enumerate() {
        if f.status != "confirmed" {
            continue;
        }
        groups.entry(key_of(f)).or_default().push(i);
    }
    for idxs in groups.into_values() {
        if idxs.len() < 2 {
            continue;
        }
        let tools: HashSet<String> =
            idxs.iter().map(|&i| deduped[i].tool.clone()).collect();
        if tools.len() < 2 {
            continue; // tool sama dua baris = bukan sumber independen
        }
        let mut sorted: Vec<&String> = tools.iter().collect();
        sorted.sort();
        let quorum = sorted.len();
        for &i in &idxs {
            deduped[i]
                .extra
                .insert("quorum".into(), serde_json::json!(quorum));
            deduped[i].extra.insert(
                "sources".into(),
                serde_json::json!(sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
            );
        }
        // --- 3. cross-confirm: L1 -> L2 saja
        for &i in &idxs {
            if deduped[i].verdict == 1 {
                deduped[i].verdict = 2;
                deduped[i].verdict_tag = crate::contract::verdict_tag(2);
                deduped[i].reportable = deduped[i].verdict >= crate::contract::MIN_REPORT_LEVEL;
                let note = format!(
                    " [FAO: cross-confirmed oleh {} sumber independen — {}]",
                    quorum,
                    sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                );
                deduped[i].description.push_str(&note);
                deduped[i]
                    .extra
                    .insert("cross_confirmed".into(), serde_json::json!(true));
            }
        }
    }

    // --- 4. family quorum (F18): keluarga header × 3 tool pada
    // (target, header) sama — metadata saja, TANPA kenaikan verdict
    // (zero-FP: kenaikan kelas tetap eksklusif quorum kunci identik).
    let mut fam_groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, f) in deduped.iter().enumerate() {
        if let Some(k) = header_family_key(f) {
            fam_groups.entry(k).or_default().push(i);
        }
    }
    for idxs in fam_groups.into_values() {
        if idxs.len() < 3 {
            continue;
        }
        let tools: HashSet<String> =
            idxs.iter().map(|&i| deduped[i].tool.clone()).collect();
        if tools.len() < 3 {
            continue; // satu tool banyak baris bukan konfirmasi lintas tool
        }
        let mut sorted: Vec<&String> = tools.iter().collect();
        sorted.sort();
        for &i in &idxs {
            if deduped[i].extra.contains_key("family_quorum") {
                continue; // jangan timpa metadata yang sudah ada
            }
            deduped[i]
                .extra
                .insert("family_quorum".into(), serde_json::json!(sorted.len()));
            deduped[i].extra.insert(
                "family_sources".into(),
                serde_json::json!(sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
            );
        }
    }

    // --- 5. evidence hash untuk semua temuan
    for f in deduped.iter_mut() {
        let h = evidence_hash(f);
        f.extra.insert("evidence_hash".into(), serde_json::json!(h));
    }

    *findings = deduped;
}

/// Tulis run-manifest.json: sha256 semua artefak run — rantai bukti
/// tingkat run (siapa pun bisa memverifikasi file tidak diubah).
pub fn write_run_manifest(
    out_dir: &std::path::Path,
    files: &[std::path::PathBuf],
) -> Result<(), String> {
    let mut entries = Vec::new();
    for p in files {
        let data = std::fs::read(p).map_err(|e| format!("manifest: {p:?}: {e}"))?;
        let full = Sha256::digest(&data);
        let mut hex = String::with_capacity(64);
        for b in full.iter() {
            hex.push_str(&format!("{b:02x}"));
        }
        let mtime = std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        entries.push(serde_json::json!({
            "file": p.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
            "bytes": data.len(),
            "sha256": hex,
            "mtime_epoch": mtime,
        }));
    }
    let doc = serde_json::json!({
        "created_at_epoch": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "files": entries,
    });
    std::fs::write(
        out_dir.join("run-manifest.json"),
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::finding_id;

    fn f(tool: &str, title: &str, target: &str, verdict: i8, category: &str, cwe: &str) -> Finding {
        let tag = crate::contract::verdict_tag(verdict);
        let id = finding_id(tool, title, Some(target), None, None);
        let mut v = serde_json::json!({
            "tool": tool, "title": title, "severity": "low",
            "description": "d", "target_url": target,
            "evidence_kind": "dns", "finding_class": "posture",
            "confidence": 1.0, "status": "confirmed",
            "verdict": verdict, "verdict_tag": tag, "id": id,
            "reportable": verdict >= 3,
            "category": category, "cwe": cwe,
        });
        if verdict == 1 {
            v["verdict_tag"] = serde_json::json!("L1 SUSPECTED - LEAD");
        }
        if verdict == 2 {
            v["verdict_tag"] = serde_json::json!("L2 REPRODUCED - LEAD");
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn quorum_upgrades_l1_to_l2_with_two_tools() {
        let mut rows = vec![
            f("banner-posture", "x", "http://t/", 1, "MISC", "CWE-693"),
            f("nuclei", "header check", "http://t/", 1, "MISC", "CWE-693"),
        ];
        correlate(&mut rows);
        for r in &rows {
            assert_eq!(r.verdict, 2, "quorum 2 harus menaikkan L1 ke L2");
            assert_eq!(r.extra["quorum"], serde_json::json!(2));
            assert_eq!(r.extra["cross_confirmed"], serde_json::json!(true));
            assert!(r.description.contains("cross-confirmed"));
        }
    }

    #[test]
    fn unconfirmed_rows_never_cross_confirm() {
        // zero-FP: dua tool yang GAGAL dengan cara sama (DNS timeout,
        // dst.) bukan konfirmasi silang — baris unconfirmed tidak ikut
        // quorum dan tidak pernah naik verdict.
        let mut rows = vec![
            {
                let mut r = f("dns-axfr-check", "gagal a", "dns:t/", 1,
                              "MISC", "CWE-200");
                r.status = "unconfirmed".into();
                r
            },
            {
                let mut r = f("spf-dmarc-posture", "gagal b", "dns:t/", 1,
                              "MISC", "CWE-200");
                r.status = "unconfirmed".into();
                r
            },
        ];
        correlate(&mut rows);
        for r in &rows {
            assert_eq!(r.verdict, 1, "unconfirmed tidak boleh naik ke L2");
            assert!(r.extra.get("cross_confirmed").is_none());
            assert!(r.extra.get("quorum").is_none());
            assert!(!r.description.contains("cross-confirmed"));
        }
    }

    #[test]
    fn l0_never_upgraded_even_with_quorum() {
        let mut rows = vec![
            f("a-tool", "obs", "http://t/", 0, "SURFACE", "CWE-200"),
            f("b-tool", "obs lain", "http://t/", 0, "SURFACE", "CWE-200"),
        ];
        correlate(&mut rows);
        assert_eq!(rows[0].verdict, 0, "inventaris tidak boleh jadi kerentanan");
        assert_eq!(rows[0].extra["quorum"], serde_json::json!(2)); // metadata tetap
    }

    #[test]
    fn same_tool_twice_is_not_quorum() {
        let mut rows = vec![
            f("tool-a", "x1", "http://t/", 1, "MISC", "CWE-693"),
            f("tool-a", "x2", "http://t/", 1, "MISC", "CWE-693"),
        ];
        correlate(&mut rows);
        for r in &rows {
            assert_eq!(r.verdict, 1, "satu tool dua baris bukan sumber independen");
            assert!(r.extra.get("quorum").is_none());
        }
    }

    #[test]
    fn l3_untouched_by_quorum() {
        let mut rows = vec![
            f("tool-a", "vuln", "http://t/", 3, "WEAKNESS", "CWE-89"),
            f("tool-b", "vuln2", "http://t/", 3, "WEAKNESS", "CWE-89"),
        ];
        correlate(&mut rows);
        assert_eq!(rows[0].verdict, 3, "L3 tidak pernah disentuh FAO");
        assert_eq!(rows[0].extra["quorum"], serde_json::json!(2));
    }

    #[test]
    fn dedup_merges_identical_ids() {
        let mut rows = vec![
            f("tool-a", "dup", "http://t/", 1, "MISC", "CWE-693"),
            f("tool-a", "dup", "http://t/", 1, "MISC", "CWE-693"),
        ];
        correlate(&mut rows);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].extra["dup_count"], serde_json::json!(2));
    }

    #[test]
    fn dedup_by_id_returns_dropped_and_keeps_first_order() {
        // merge lintas-mode: baris unik + 2 duplikat id sama + baris unik
        // lagi — urutan baris pertama dipertahankan, jumlah dibuang akurat
        let mut rows = vec![
            f("tool-a", "unik1", "http://t/", 1, "MISC", "CWE-693"),
            f("tool-a", "dup", "http://t/", 1, "MISC", "CWE-693"),
            f("tool-a", "dup", "http://t/", 1, "MISC", "CWE-693"),
            f("tool-a", "dup", "http://t/", 1, "MISC", "CWE-693"),
            f("tool-a", "unik2", "http://t/", 1, "MISC", "CWE-693"),
        ];
        let dropped = dedup_by_id(&mut rows);
        assert_eq!(dropped, 2, "2 salinan berlebih dibuang (3 baris dup)");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].title, "unik1");
        assert_eq!(rows[1].title, "dup");
        assert_eq!(rows[2].title, "unik2");
        assert_eq!(rows[1].extra["dup_count"], serde_json::json!(3),
                   "dup_count = total kemunculan (1 + 2 duplikat)");
        assert!(rows[0].extra.get("dup_count").is_none());
    }

    #[test]
    fn dedup_by_id_noop_on_unique() {
        let mut rows = vec![
            f("tool-a", "x", "http://t/", 1, "MISC", "CWE-693"),
            f("tool-a", "y", "http://t/", 1, "MISC", "CWE-693"),
        ];
        let dropped = dedup_by_id(&mut rows);
        assert_eq!(dropped, 0);
        assert_eq!(rows.len(), 2);
    }

    fn with_header(mut x: Finding, header: &str) -> Finding {
        x.extra.insert("header".into(), serde_json::json!(header));
        x
    }

    #[test]
    fn family_quorum_header_x3_is_metadata_only() {
        // 3 tool berbeda melapor soal HSTS pada target sama; (category,
        // cwe) dibuat beda semua supaya quorum kunci identik TIDAK picu —
        // yang teruji murni family quorum: metadata tanpa kenaikan verdict
        let mut rows = vec![
            with_header(f("banner-posture", "a", "http://t/", 1, "MISC", "CWE-100"),
                        "strict-transport-security"),
            with_header(f("http-security-headers", "b", "http://t/", 1, "MISC", "CWE-200"),
                        "Strict-Transport-Security"),
            with_header(f("csp-analyzer", "c", "http://t/", 1, "MISC", "CWE-300"),
                        "strict-transport-security"),
        ];
        correlate(&mut rows);
        for r in &rows {
            assert_eq!(r.extra["family_quorum"], serde_json::json!(3));
            assert_eq!(r.verdict, 1, "family quorum TIDAK menaikkan kelas");
            assert!(r.extra.get("cross_confirmed").is_none());
            assert!(r.extra.get("quorum").is_none(),
                    "kunci identik sengaja dibuat beda agar tidak ikut picu");
            let srcs = r.extra["family_sources"].as_array().unwrap();
            assert_eq!(srcs.len(), 3);
        }
    }

    #[test]
    fn family_quorum_needs_three_distinct_tools() {
        let mut rows = vec![
            with_header(f("a-tool", "x", "http://t/", 1, "MISC", "CWE-693"),
                        "content-security-policy"),
            with_header(f("b-tool", "y", "http://t/", 1, "MISC", "CWE-693"),
                        "content-security-policy"),
        ];
        correlate(&mut rows);
        for r in &rows {
            assert!(r.extra.get("family_quorum").is_none(), "2 tool bukan family quorum");
        }
    }

    #[test]
    fn findings_without_header_tag_never_get_family_quorum() {
        let mut rows = vec![
            f("a-tool", "x", "http://t/", 1, "MISC", "CWE-693"),
            f("b-tool", "y", "http://t/", 1, "MISC", "CWE-693"),
            f("c-tool", "z", "http://t/", 1, "MISC", "CWE-693"),
        ];
        correlate(&mut rows);
        for r in &rows {
            assert!(r.extra.get("family_quorum").is_none(),
                    "tanpa tag header eksplisit -> bukan keluarga header");
        }
    }

    #[test]
    fn same_tool_many_header_rows_is_not_family_quorum() {
        let mut rows = vec![
            with_header(f("satu-tool", "x1", "http://t/", 1, "MISC", "CWE-693"),
                        "x-frame-options"),
            with_header(f("satu-tool", "x2", "http://t/", 1, "MISC", "CWE-693"),
                        "x-frame-options"),
            with_header(f("satu-tool", "x3", "http://t/", 1, "MISC", "CWE-693"),
                        "x-frame-options"),
        ];
        correlate(&mut rows);
        for r in &rows {
            assert!(r.extra.get("family_quorum").is_none());
        }
    }

    #[test]
    fn evidence_hash_deterministic_and_changes_with_evidence() {
        let mut r = f("t", "x", "http://t/", 1, "MISC", "CWE-693");
        r.extra.insert(
            "request".into(),
            serde_json::json!("GET / HTTP/1.1"),
        );
        let h1 = evidence_hash(&r);
        let h2 = evidence_hash(&r);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // audit 2026-10: digest SHA-256 penuh
        r.extra.insert("response".into(), serde_json::json!("HTTP/1.1 200"));
        assert_ne!(evidence_hash(&r), h1, "bukti berubah -> hash berubah");
    }
}
