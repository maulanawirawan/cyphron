# Cyphron Core — ROADMAP penyempurnaan timeline

> Menggantikan fase-fase lama yang bertentangan dengan arah "standalone / dari scratch".
> Kondisi awal v0.1: runtime jalan end-to-end dengan 7 engine sendiri, gate kode, verifier, audit, laporan.

## Fase R1 — Engine perluasan (gantikan "Fase 2 lama")
- [ ] Session/cookie jar + login flow (grey-box probing)
- [ ] Form POST probing (union/error-based SQLi via POST body)
- [ ] NoSQL injection probe (operator `{"$ne": null}` style)
- [ ] SSRF probe (callback ke listener lokal), open-redirect probe
- [ ] SSTI probe (`{{7*7}}` marker family), CORS misconfig audit
- [ ] TLS quick-check (cert expiry, weak protocol) via stdlib `ssl`
- [ ] Semua tetap: risk_tags + gate + verifier + audit
- [ ] `ssrf_probe` — engine Skill 68: URL grammar (schemes/localhost/blocked v4+/
      suffixes/credentials/encodings) + all-DNS-answers + manual redirect hops;
      korpus dari skill 68; stdlib (urlparse, ipaddress, socket)
- [ ] `proxy_trust_probe` — engine Skill 69: kirim forged XFF chain
      ("1.2.3.4, 5.6.7.8" / "203.0.113.7, 10.1.2.3, 10.1.2.4"), deteksi refleksi
      IP di body/headers + perilaku tanpa TRUSTED_PROXIES
- [ ] `upload_probe` — engine Skill 71: multipart stdlib; korpus: PNG valid,
      EXIF, double-extension, corrupt, near-limit, polyglot; cek magic-byte enforcement
- [ ] `security_headers` v2 — upgrade Skill 72: kualitas CSP (unsafe-inline,
      wildcard, default-src hilang) + saran nonce
- [ ] Assisted modes (butuh input user, bukan generic): `replay_probe` (template
      callback dari user, Skill 67/70), `route_inventory` (walk repo Next.js
      convention, Skill 66)
- [ ] R3 seed: tabel AP1–AP10 (Skill 73) jadi taksonomi default chain graph

## Fase R2 — Skill atomization (gantikan "pangkas 65 → 15-25")
- [ ] Skema skill atomik: {id, preconditions, inputs, outputs, allowed_tools, steps[], eval_cases[]}
- [ ] Generator: prose skill .kimchi → kandidat skill atomik (deterministik, review manual)
- [ ] Index SQLite (FTS5) untuk retrieval; embedding HANYA saat LLM slot dipasang
- [ ] Target: cakupan 65 skill lama terpetakan ke N skill atomik (N boleh ratusan; arah 7500 tetap terbuka karena unit-nya kecil & ter-eval)

## Fase R3 — Verifier & chaining (perluasan Fase 5 lama)
- [ ] Re-probe konfirmasi (duplikasi request untuk menekan false positive)
- [ ] Attack chain graph di WorldModel (secret → akses → IDOR) + skor dampak
- [ ] Dedup lintas-engine (fingerprint + CVE/CWE normalisasi)

## Fase R4 — LLM slot (ketika tim sudah memilih)
- [ ] `LLMPlanner` implement `plan()` + narasi laporan; schema-validated output
- [ ] Fallback deterministik WAJIB tetap ada (model mati ≠ scan mati)
- [ ] Gate/verifier/audit tetap 100% kode

## Fase R5 — Skill synthesis → ferments
- [ ] Pola sukses berulang → skill atomik status `proposed` di `.kimchi/ferments/`
- [ ] CLI `cyphron ferments list/promote` (promote = review manusia + daftar ke agent-config.yaml)

## Fase R6 — Eval harness (gantikan Fase 8 lama)
- [ ] Lab: `../juice-shop` (sudah ada) + fixture internal
- [ ] Metric per engine: detection rate, FP rate, mean time, request count
- [ ] Regression gate: skor tak boleh turun antar commit
- [ ] Laporan `docs/EVAL.md`
- [ ] Eval case per skill panenan: 66→route guard hilang di fixture; 67→webhook
      unsigned + duplikat di fixture; 68→`/fetch?url=` ke metadata; 69→echo-XFF;
      70→callback duplikat; 71→upload double-extension; 72→CSP unsafe-inline;
      73→chain secret(.env) → endpoint internal di world model

## Aturan tetap (tidak dinegosiasi)
- Tanpa third-party di core runtime. Non-stdlib hanya via subprocess terisolasi + flag eksplisit.
- Tool aktif tanpa dokumen otorisasi valid = ditolak kode. Selamanya.
- Setiap temuan: bukti atau tidak dilaporkan sebagai confirmed.
- Satu agent kerjakan sendiri, tidak spawn sub-agent paralel (limit concurrency akun).
