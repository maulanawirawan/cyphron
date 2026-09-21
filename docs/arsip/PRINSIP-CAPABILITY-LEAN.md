# CYPHRON — CAPABILITY ROADMAP (lean, field-driven)

> **[DIKONSOLIDASIKAN 21-09-2026] Status terkini seluruh item ada di [STATUS-MASTER.md](STATUS-MASTER.md) — dokumen ini jadi arsip rincian.**

> Prinsip: kemampuan ditambah hanya jika ada pelajaran lapangan yang
> membutuhkannya. Stdlib-only, deterministik, zero-FP by construction.
> Dokumen ini sengaja pendek — roadmap panjang = utang, bukan aset.

## 0. Prinsip desain: Research Loop

Pembeda AI scanner vs AI security researcher adalah loop ini. Setiap engine
baru wajib mengikuti pola:

```text
SOURCE/OBSERVATION
      ↓
HYPOTHESIS (hipotesis eksplisit + bukti apa yang akan membuktikannya)
      ↓
EXPERIMENT (probe bounded, benign, diferensial)
      ↓
OBSERVE (bandingkan baseline vs attack)
      ↓
CONFIRM / REJECT
      ↓ (reject) → hipotesis baru, bukan laporan spekulatif
```

FP-guard wajib tiap engine (pelajaran lapangan 2026-09):
marker statis ≠ sinyal dinamis (uji baseline dulu); atribusi respons via
redirect ditolak; filename-lookalike difilter; cease-on-data setelah bukti
pertama; bukti yang tidak bisa direproduksi = NOT claimed.

## 1. Yang SUDAH ada (per 2026-09-12)

| Lapisan | Komponen |
|---|---|
| Offensive runtime | 69 engine (web, API, WP fleet, XML-RPC, DNS, JS, email/TLS, authz/BOLA/priv-matrix, lockout, wp_dataexp, LLM probe) |
| Security Graph | `graph.py` KnowledgeGraph v1 |
| Validation | 3-gate truth guard (`verification.py`) + `verifier.finalize` + **Validator Quorum** (`quorum.py`) |
| Evidence | Finding request/response + **Evidence Ledger** `Finding.evidence_chain` (kind/at/sha256) |
| Composition | **Attack Chain Composer** (`chaining.py`) — impact gabungan > impact per-temuan |
| Drift | **Attack Surface Drift** (`drift.py` + `cyphron drift`) |
| Remediation | `remediate.py` + `cyphron fix` |
| Regression | `cyphron verify` (re-scan vs baseline → fixed/open/new) |
| Planner | hipotesis H-* + budget ledger, auto-select engine by world state |
| Skills | registry retrieval (.kimchi pack) |

## 2. Fabric baru (2026-09-12) — cara pakai

- **Attack Chain Composer** — `from cyphron.chaining import compose`;
  otomatis jalan di akhir scan (`ScanSummary.attack_chains`). Contoh
  lapangan: user-enum + no-lockout → "credential spraying pipeline" (High).
- **Validator Quorum** — `from cyphron.quorum import adjudicate, summarize`;
  3 validator rule-based → CONFIRMED / PROBABLE / INCONCLUSIVE / REJECTED.
  CONFIRMED selalu menuntut bukti runtime yang reproducible.
- **Evidence Ledger** — `finding.attach_evidence(kind, detail)`; provenance
  ber-hash untuk jawaban "kenapa Cyphron yakin".
- **Surface Drift** — `cyphron drift --old old.json --new new.json`;
  added/removed/changed + klasifikasi relevansi + antrian re-scan tertarget.

## 3. Increment berikutnya — digerakkan pelajaran lapangan

Tidak ada arsitektur besar yang dijadwalkan. Increment berikutnya hanya
muncul dari satu sumber: **temuan nyata di lapangan**:

1. Temuan baru terjadi → tekniknya jadi engine baru (pola: wp_probe,
   lockout, wp_dataexp, xmlrpc_probe lahir dari kasus nyata).
2. FP baru tertangkap → FP-guard baru masuk engine terkait + test regresi.
3. Kombinasi temuan baru yang menarik → rule baru di `chaining.RULES`.
4. Kebutuhan laporan baru → perluasan pdfout/reporting.

Aturan mutu tetap: zero-FP, cease-on-data, bounded & benign probes, stdlib
only, suite hijau sebelum push, tanpa LLM di jalur validasi.
