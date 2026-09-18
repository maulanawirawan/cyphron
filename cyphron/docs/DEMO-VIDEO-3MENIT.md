# Storyboard Video Demo 3 Menit (untuk direkam)

> Target: korporat/lead teknis. Tanpa musik gimmick; voice-over Indonesia
> santai-profesional. Semua tayangan dari suite nyata (bukan mockup).

| Shot | Durasi | Visual | Voice-over inti |
|---|---|---|---|
| 1 | 0:00-0:15 | Terminal: `python -m cyphron check --target ... --auth ...` lalu refusal tanpa auth | "Ini Cyphron. Otorisasi ditegakkan kode — tanpa dokumen izin, semua aksi aktif ditolak." |
| 2 | 0:15-0:45 | `scan` berjalan pada lab lokal; log fase eskalasi + budget | "Planner deterministik membaca world model: probe dulu, pola dipelajari, eskalasi terukur — semua tunduk budget." |
| 3 | 0:45-1:15 | PDF laporan: cover, verdict ladder, tabel verdict ADA/TIDAK | "Laporannya berisi keputusan, bukan tebakan. L3 ke atas = temuan dengan bukti reproduktif. Sisanya dilabel LEAD." |
| 4 | 1:15-1:45 | Detail temuan: request-response + PoC curl + chip L3 + path graph | "Setiap temuan membawa bukti dan jalannya: sampai sini lewat apa — tergambar." |
| 5 | 1:45-2:15 | `fix` lalu `verify`: delta fixed/open/new | "Cyphron menutup lingkaran: buat rencana perbaikan, lalu buktikan dengan scan ulang." |
| 6 | 2:15-2:40 | `benchmark` + `god-report` (KB offline) | "Klaim pakai angka: precision/recall/F1, ambiguitas ditolak. Knowledge base NVD lokal jadi lead pasif tanpa satu request." |
| 7 | 2:40-3:00 | `redteam` coverage matrix + `adapters` multi-runtime; closing logo | "Dari matriks MITRE-lite sampai engine polyglot — satu runtime Python, satu pintu guardrail. Cyphron: temuan yang bisa dibuktikan." |

Produksi: rekam 1280x720 terminal (font besar), PDF di layar penuh, tanpa
data klien. Simpan di `landing/reports/` (lokal) — jangan commit berat ke
repo; commit storyboard ini saja.
