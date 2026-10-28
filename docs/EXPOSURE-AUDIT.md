# Exposure Audit — alur client (F48-F54)

> Produk use-case: client menyerahkan **bundle/artefak miliknya**
> (hasil build frontend, Electron, APK, extension) → cyphron
> menunjukkan "apa yang dilihat tool reverse-engineering di dalamnya
> SEBELUM attacker melihatnya" → PDF laporan bahasa awam.
> Tanggung jawab otorisasi = pemilik aset (client); NOL jaringan;
> read-only; zero-FP (signature ketat, tanpa tebakan).

## Perintah (satu alur, dua langkah)

```bash
# 1) audit exposure (file tunggal / pohon dist / arsip kemasan)
python tools/bundle_exposure.py --dir dist/ --out findings/exposure.json
python tools/bundle_exposure.py --file app.apk --out findings/exposure.json

# 1b) binary (exe/dll/so/firmware): lapisan string + offset byte
#     + provenance section (ELF: .rodata dll.)
python tools/binary_strings_surface.py --file lib.so --out findings/binary.json

# 2) PDF laporan bahasa awam (TERBUKTI/PERLU DICEK/BERSIH/...)
python tools/report_pdf.py --findings findings/exposure.json \
    --out laporan-exposure-client.pdf \
    --title "Exposure Audit — <nama client>"
```

## Format yang didukung

| Input | Isi yang di-scan |
|---|---|
| .js/.mjs/.cjs/.ts/.json/.html/.py (file/pohon) | URL absolut, path API literal, secret ber-format (sk_live_/AKIA/ghp_/xoxb/AIza), variabel bernama secret, flag admin/debug |
| app.asar (Electron) | seluruh entri teks di dalam arsip + sourcemap |
| app.apk / .zip | seluruh entri; classes.dex/.so lewat strings surface |
| .crx (Chrome extension) | ZIP payload setelah header Cr24 |
| .map (sourcemap) | lead CWE-540 + sourcesContent diaudit; `--restore` menulis source asli (anti-traversal) |
| binary (exe/dll/so/firmware) | string ASCII + UTF-16LE dengan offset byte + provenance section ELF (.rodata dll.) |

## Interpretasi hasil

- **URL / path API (L0 inventaris)** — fakta: terbaca siapa pun yang
  memegang bundle. Bukan kerentanan; bahan peta permukaan.
- **Secret ber-format / variabel secret (L1 lead)** — verifikasi
  manual: nyata → rotasi + pindah server-side; placeholder → catat.
- **Flag admin/debug (L1, CWE-489)** — jalur istimewa di kode klien.
- **Sourcemap ter-deploy (L1, CWE-540)** — source asli pra-minify
  terekspos; isinya ikut diaudit otomatis.
- Verdict ladder tetap berlaku: hanya L3+ (PoC) yang reportable —
  alat ini sengaja berhenti di lead (L1) karena paparan statis bukan
  bukti eksploitasi.

## Batas jujur

Analisis statis lapisan string/struktur saja — bukan disassembler,
bukan analisis dinamis. Obfuscation menaikkan biaya attacker, tidak
mencegah analisis. Pertahanan nyata tetap server-side (authz, rate
limit, canary — docs/ANTIBOT-DEFENSE-BLUEPRINT.md).
