# F66 — Batch agresif pasca-Black October (2026-10-28)

> **Prinsip batch ini**: "lebih agresif" = **cakupan + kedalaman bukti**,
> bukan kekerasan request. Semua modul tetap read-only/bounded, signature
> ketat, zero-FP, dan ladder verdict tidak dilonggar. Tidak ada modul
> brute-force, DoS, atau mass-exploit.

## 1. Pemicu

Riset ulang 2026-10-28 (KEV + berita) menemukan delta di luar cakupan
F61:

| Item | CVE | Status verifikasi | Dasar |
|---|---|---|---|
| Bricksforge (WP plugin) | CVE-2026-85097 | headline-level (THN) | CVSS 10.0, upload+eksekusi PHP, eksploitasi 07 Okt |
| Adobe Commerce / Magento | CVE-2026-48356 | KEV 2026-10-27 | headline "PolyShell"; detail body 403 |
| Oracle E-Business Suite | CVE-2026-101767 | headline-level | CVSS 9.8 unauth SQLi->RCE, probing 27 Okt |
| Plex Media Server | CVE-2026-96652 (+96654/96655/96656) | KEV 2026-10-20 | rantai SSRF/token theft/file write |
| PHP (tambahan) | CVE-2026-115560 | mitigasi-only | belum ada patch — di luar KB |
| AGENTS.md/CLAUDE.md hijack | — | laporan BleepingComputer 2026-10-25 | file instruksi agen di Downloads |

**Aturan**: item headline-level tetap dipakai **hanya** sebagai seed
watchlist product-level (maks L1, tanpa klaim versi). Nomor fix/rentang
versi tidak difabrikasi — KB operator hanya diisi dari advisory vendor.

## 2. Skill baru (registry 83 -> 88)

| Skill | Safety class | Request | Bukti / zero-FP |
|---|---|---|---|
| `php-posture` | bounded-requests | 4 GET | marker PHP (X-Powered-By/PHPSESSID/error body), easter-egg expose_php (content-type image/gif + body GIF89a), phpinfo (3 signature sekaligus) |
| `brotli-stack-surface` | 1-request | 1 GET (Accept-Encoding br) | token utuh `br` di Content-Encoding; marker Express/connect.sid/__NEXT_DATA__/Kestrel/ASP.NET |
| `wp-plugin-surface` | bounded-requests | 6 GET | readme.txt publik 5 plugin kandidat (bricksforge/elementor/woocommerce/contact-form-7/wordpress-seo); bentuk readme wajib |
| `magento-surface` | bounded-requests | 3 GET | /magento_version (`Magento/X.Y.Z`), login, downloader; token word-boundary |
| `agent-instruction-exposure` | bounded-requests | 5 GET | /AGENTS.md,/CLAUDE.md,/.cursorrules,/.mcp.json,/.windsurfrules; AGENTS/CLAUDE/MCP = L2 CWE-538; fallback HTML ditolak |

### Kontrak bukti

- **L0** — inventaris/SURFACE (deteksi teknologi, Brotli aktif).
- **L1** — lead (versi ter-expose, stack Node, kandidat file aturan).
- **L2** — phpinfo terbuka, file instruksi agen ter-expose (signature
  kuat, bukan fallback SPA).
- Tidak ada jalur L3+ di batch ini (butuh PoC/impact, tetap domain
  playbook lab).

## 3. Integrasi

- `skills/registry.json`: 5 entri baru (total **88**).
- `tools/cve_matcher.py`: `ALLOWED_SOURCE_TOOLS` += `php-posture`,
  `brotli-stack-surface`, `wp-plugin-surface`, `magento-surface`.
- `assets/intel/watchlist-seeds.json`: 7 -> **11** seed (+Bricksforge,
  Adobe Commerce, Oracle EBS, Plex2Shell).
- Sync watchlist: `window-20261028` = **94 entri** (11 seed + 83 NVD
  critical), delta +13 dari window-20261025.
- Docs: `docs/CVE-MATCHER.md` §8 diperbarui; riset:
  `work/study/black-october-2026-intel.md` UPDATE 4.

## 4. Verifikasi

- Test baru: `tests/test_f66_posture_batch.py` — **17 test**, nol jaringan
  (urlopen di-mock), termasuk kontrak `validate_finding`, guard return
  shape, dan rantai watchlist bricksforge -> CVE-2026-85097.
- Pin registry 83 -> 88 di 9 file test (konvensi batch).
- Suite penuh: **726 test hijau** (1 skip terdokumentasi).

## 5. Antrian berikutnya

1. **KB Bricksforge/Magento**: HOLD sampai advisory vendor resmi memuat
   nomor fix (no fabrication).
2. **Skill banner Oracle EBS / Plex**: seed sudah siap; deteksi banner
   belum dibangun (bounded 2-3 GET, token ketat).
3. **Playbook prompt-injection MCP live** (F59 -> target MCP nyata):
   butuh gate tier aktif + lab endpoint.
4. **KEV watch**: php2shell/GitLab/Node/Bricksforge/Oracle EBS — watchlist
   otomatis kalah oleh KEV saat masuk (dedup sudah diuji).
