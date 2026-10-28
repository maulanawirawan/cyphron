# EGRESS SETUP — cara membuat pool proxy milik sendiri (F20c)

> Fitur `--proxies`/`--proxy` butuh endpoint egress NYATA di mesin lain.
> Proxy yang jalan di laptop yang sama **tidak mengubah IP exit** —
> percuma untuk rotasi. Ini panduan membuatnya dalam 5–15 menit.

## Prinsip

- **IP exit** ditentukan mesin tempat proxy berjalan. Mau N IP berbeda =
  butuh N mesin (VPS/hosting murah, ±$3/bulan per IP).
- **Identitas aplikasi** (User-Agent) ditangani `--ua browser`.
- **Audit**: tiap skill tercatat lewat proxy mana di `data.sources`
  (kredensial otomatis direduksi). Bukti tetap bisa dipertanggung-
  jawabkan walau egress berputar.

## Resep 1 — SSH SOCKS tunnel (paling cepat, nol install di VPS)

Punya akses SSH ke VPS mana pun (Panels/Vultr/DigitalOcean/VPS lokal
ISP)? Satu perintah = satu proxy socks5:

```bash
# di mesin kamu, per VPS satu tunnel (port lokal beda-beda):
ssh -N -D 1080 user@vps1.example &
ssh -N -D 1081 user@vps2.example &
```

`proxies.txt`:
```
socks5://127.0.0.1:1080
socks5://127.0.0.1:1081
```

Wajib: `pip install pysocks` di mesin ini (skill memasang dukungan
socks5 otomatis; tanpa PySocks ada peringatan keras di stderr dan
request jalan langsung — bukan diam-diam).

## Resep 2 — HTTP proxy di VPS (nol dependensi Python)

Di tiap VPS (Debian/Ubuntu), pilih salah satu:

**tinyproxy (paling ringan):**
```bash
apt install -y tinyproxy
# /etc/tinyproxy/tinyproxy.conf:
#   Port 9001
#   Allow <IP-rumah-kamu>/32     # JANGAN terbuka publik!
systemctl restart tinyproxy
```

**squid:**
```bash
apt install -y squid
# /etc/squid/squid.conf:
#   http_port 9002
#   acl myip src <IP-rumah-kamu>/32
#   http_access allow myip
#   http_access deny all
systemctl restart squid
```

`proxies.txt`:
```
http://vps1.example:9001
http://vps2.example:9002
```

Bila butuh autentikasi: `http://user:pass@vps:port` (kredensial otomatis
direduksi di merged doc, tidak pernah ikut ke file hasil).

## Resep 3 — satu VPS, banyak IP (IP tambahan di NIC yang sama)

VPS dengan beberapa IP (add-on IP / failover IP) bisa menjalankan
beberapa instance tinyproxy dengan `Bind <ip-per-instance>` — satu
mesin, N egress. Murah untuk rotasi kecil (3–5 IP).

## Anti-pattern (JANGAN)

1. **Free public proxy list** — proxy gratis dikelola orang asing:
   trafik bisa dilihat/diubah (MITM), 90% mati dalam hitungan jam, dan
   IP-nya sering sudah masuk blocklist. Untuk scanning yang hasilnya
   jadi laporan keamanan, ini membuka pintu manipulasi bukti.
2. **Proxy di laptop sendiri / Docker lokal** — IP exit tetap IP rumah;
   rotasi tidak terjadi.
3. **Proxy terbuka tanpa allowlist/auth** — VPS-mu akan jadi proxy
   orang lain dalam hitungan jam (abuse), IP-nya kena blocklist.

## Pemakaian

```bash
cyphron scan --mode tier0 --domain contoh.id --target https://contoh.id/ \
    --proxies proxies.txt --ua browser
```

Cek hasil: `data.sources[*].proxy` di findings.json menunjukkan egress
per skill; `data.low_profile.strategy` = "round-robin-per-skill".
