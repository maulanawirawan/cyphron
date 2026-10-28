# Nightrun — scan tier0 harian + drift detection (F23)

Orchestrator scan malam: tier0 (data publik, nol testing aktif) ke semua
program target dari satu config, lalu deteksi drift temuan vs run
sebelumnya (by ID deterministik + perubahan verdict) dan akumulasi
ringkasan mingguan + PDF.

## Config

File JSON (contoh `nightrun.json` di root repo, TIDAK ikut release):

```json
{
  "note": "opsional",
  "programs": [
    {"id": "prog-a", "name": "Nama Program", "domain": "contoh.go.id",
     "target": "https://contoh.go.id/", "budget": 32},
    {"id": "prog-b", "domain": "contoh2.go.id", "budget": 0}
  ]
}
```

- `id` unik, `domain` wajib; `target` default `https://<domain>/`;
- `budget` = `--max-requests` untuk scan itu (int >= 0). **budget 0 =
  program di-skip dengan baris audit** (bukan senyap);
- konflik config (id duplikat, key tak dikenal, budget negatif) =
  error keras exit 2 — fail-closed.

## Pemakaian

```
python tools/nightrun.py --config nightrun.json [--out findings/night-run]
cyphron nightrun --config nightrun.json --dry-run   # rencana tanpa scan
```

Output per run (`findings/night-run/<run-id>/`): `nightrun-summary.json`
+ `nightrun-report.pdf` (bila typst tersedia). State per program yang
stabil lintas-run: `findings/night-run/state/<id>/` (findings.json +
drift.json — drift dihitung SEBELUM snapshot lama ditimpa, pola
program_sweep). Akumulasi mingguan: `findings/night-run/weekly-summary.json`.

Exit code: 0 semua scan ok / skip-by-budget; 1 ada scan gagal (scheduler
bisa alert); 2 config error.

## Windows scheduler (schtasks siap-pakai — TIDAK di-install otomatis)

Jalankan manual sekali di PowerShell (dari root repo):

```powershell
schtasks /Create /TN "cyphron-nightrun" /SC DAILY /ST 02:00 /TR `
  "python tools\nightrun.py --config nightrun.json --out findings\night-run --no-pdf"
```

Catatan:
- `/TR` maks ~260 karakter — kalau path repo panjang, bungkus di
  `run-nightrun.cmd` satu baris lalu pakai path .cmd di `/TR`.
- Cek log: `schtasks /Query /TN "cyphron-nightrun" /V`; hasil run
  selalu ada di `nightrun-summary.json` (exit code != 0 = gagal).
- Hapus: `schtasks /Delete /TN "cyphron-nightrun" /F`.
- PDF butuh typst (lihat docs/INSTALL.md); `--no-pdf` kalau tidak perlu.
