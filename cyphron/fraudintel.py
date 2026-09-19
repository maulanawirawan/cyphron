"""fraudintel — Fraud-intel & attribution kit (defensive, pasif).

Kasus: klien korban penipuan hanya punya NOMOR HP dan/atau NOMOR REKENING
pelaku, dan minta bantuan analisis. Yang Cyphron berikan:

1. IDENTIFIKASI STRUKTUR (deterministik, dengan ambiguity rejection):
   - nomor HP -> normalisasi E.164 + operator berdasar blok prefix publik
     (label confidence; blok prefix bisa berpindah antar operator);
   - nomor rekening -> kandidat bank berdasar panjang/pola terdokumentasi;
     ambigu = DILABEL AMBIGU, bukan ditebak.
2. DOSSIER ESKALASI RESMI: langkah pengaduan yang benar (cekrekening.id,
   OJK 157, bank terkait, Polri Subdit Tipid Siber), checklist bukti, dan
   template laporan — karena resolusi identitas pelaku (nama/alamat dari
   nomor/rekening) HANYA bisa lewat proses hukum/data operator-bank.

BATAS Tegas (zero-rationalization):
- TIDAK melakukan resolusi identitas orang; tidak mengakses/memakai data
  kebocoran (data sim card/kebocoran KTP = ilegal, UU PDP & UU ITE);
- tidak scraping akun pribadi; tidak impersoanasi;
- identitas nasabah/pelanggan hanya bisa dibuka oleh operator/bank/penegak
  hukum lewat prosedur resmi — tugas Cyphron adalah menyiapkan paket
  pengaduan yang kuat, bukan menggantikan kewenangan itu.

Redaksi: keluaran dossier default MENGUNTING nomor (PII discipline) karena
laporan bisa diteruskan ke banyak pihak.
"""

from __future__ import annotations

from pathlib import Path

# ------------------------------------------------------- prefix operator ID
# Blok prefix publik (bisa berpindah antar operator — selalu label
# confidence + tanggal pemetaan).
_CARRIERS: tuple[tuple[str, str, str], ...] = (
    # prefix, operator/group, catatan
    ("811", "Telkomsel", "KartuHalo/simPATI"), ("812", "Telkomsel", ""),
    ("813", "Telkomsel", ""), ("821", "Telkomsel", ""),
    ("822", "Telkomsel", ""), ("823", "Telkomsel", ""),
    ("851", "Telkomsel/by.U", "blok 851 termasuk by.U"),
    ("852", "Telkomsel", ""), ("853", "Telkomsel", ""),
    ("814", "Indosat Ooredoo Hutchison", "IM3"),
    ("815", "Indosat Ooredoo Hutchison", "IM3"),
    ("816", "Indosat Ooredoo Hutchison", "IM3"),
    ("855", "Indosat Ooredoo Hutchison", "IM3/Tri merger 2023"),
    ("856", "Indosat Ooredoo Hutchison", "IM3/Tri merger 2023"),
    ("857", "Indosat Ooredoo Hutchison", "IM3/Tri merger 2023"),
    ("858", "Indosat Ooredoo Hutchison", "IM3/Tri merger 2023"),
    ("817", "XL Axiata", ""), ("818", "XL Axiata", ""),
    ("819", "XL Axiata", ""), ("859", "XL Axiata", ""),
    ("877", "XL Axiata", ""), ("878", "XL Axiata", ""),
    ("831", "Axis (grup XL)", ""), ("832", "Axis (grup XL)", ""),
    ("833", "Axis (grup XL)", ""), ("838", "Axis (grup XL)", ""),
    ("881", "Smartfren", ""), ("882", "Smartfren", ""),
    ("883", "Smartfren", ""), ("884", "Smartfren", ""),
    ("885", "Smartfren", ""), ("886", "Smartfren", ""),
    ("887", "Smartfren", ""), ("888", "Smartfren", ""),
    ("889", "Smartfren", ""),
    ("891", "Tri (H3I)", ""), ("892", "Tri (H3I)", ""),
    ("893", "Tri (H3I)", ""), ("894", "Tri (H3I)", ""),
    ("895", "Tri (H3I)", ""), ("896", "Tri (H3I)", ""),
    ("897", "Tri (H3I)", ""), ("898", "Tri (H3I)", ""),
    ("899", "Tri (H3I)", ""),
)
_MAPPING_NOTE = ("pemetaan prefix = blok publik umum; blok bisa berpindah "
                 "operator (porting) — verifikasi akhir tetap milik operator")

# --------------------------------------------------------- kandidat bank ID
# Panjang rekening terdokumentasi umum (belum tentu lengkap/bermutakhir —
# identifikasi bank dari nomor TIDAK deterministik penuh -> ambigu dilabel).
_BANK_LENGTHS: tuple[tuple[str, tuple[int, ...], str], ...] = (
    ("BCA", (10,), "sering mulai 0/5/8"),
    ("BNI", (10,), ""),
    ("Bank Mandiri", (13,), ""),
    ("BRI", (15,), ""),
    ("Bank Syariah Indonesia (BSI)", (10,), ""),
    ("CIMB Niaga", (13, 14), ""),
    ("Bank Danamon", (10,), ""),
    ("Bank Permata", (10,), ""),
    ("Bank Neo Commerce", (10,), ""),
    ("Bank Jago", (10,), ""),
    ("Jenius (BTPN)", (12,), "umumnya mulai 9"),
    ("SeaBank", (11,), ""),
    ("Bank Keb Hana", (10, 13), ""),
    ("Bank Mega", (10,), ""),
    ("Bank Sahabat Sampoerna", (10,), ""),
)


def _digits(raw: str) -> str:
    return "".join(c for c in str(raw) if c.isdigit())


def mask_phone(e164: str) -> str:
    """+6283865063443 -> +62 838-6506-**** (redaksi PII default)."""
    if e164.startswith("+62") and len(e164) >= 12:
        rest = e164[3:]
        head = rest[:7]
        return f"+62 {head[:3]}-{head[3:]}-" + "*" * max(len(rest) - 7, 0)
    return "+" + "*" * max(len(e164) - 1, 0)


def mask_account(num: str) -> str:
    # redaksi dossier yang diteruskan ke banyak pihak: sisakan MAKSIMAL 4 digit
    # terakhir (rekening pendek jangan tampil utuh)
    return "*" * max(len(num) - 4, 0) + num[-4:]


def analyze_phone(raw: str) -> dict:
    digits = _digits(raw)
    # normalisasi: 62xxx / 0xxx / 8xx
    if digits.startswith("62"):
        national = digits[2:]
    elif digits.startswith("0"):
        national = digits[1:]
    else:
        national = digits
    e164 = "+62" + national
    prefix3 = national[:3]
    matches = [(c, note) for p, c, note in _CARRIERS if p == prefix3]
    prefix4 = national[:4]
    matches4 = [(c, note) for p, c, note in _CARRIERS if p == prefix4]
    if matches4:
        carrier, note = matches4[0]
        candidates = [{"operator": carrier, "note": note,
                       "confidence": 0.75}]
        ambiguous = False
    elif matches:
        candidates = [{"operator": c, "note": note, "confidence": 0.7}
                      for c, note in matches]
        ambiguous = len(candidates) > 1
    else:
        candidates = []
        ambiguous = True
    return {
        "kind": "phone",
        "input_valid": 9 <= len(national) <= 12
        and national.startswith("8"),
        "e164_masked": mask_phone(e164),
        "prefix": prefix3,
        "candidates": candidates,
        "ambiguous": ambiguous or not candidates,
        "mapping_note": _MAPPING_NOTE,
        "identity_resolution": ("TIDAK dilakukan — identitas pelanggan hanya "
                                "bisa dibuka operator lewat prosedur resmi "
                                "(kepolisian/permintaan sah)"),
    }


def analyze_account(raw: str, bank_hint: str | None = None) -> dict:
    num = _digits(raw)
    hint = (bank_hint or "").strip().lower()
    candidates = []
    for name, lengths, note in _BANK_LENGTHS:
        if len(num) in lengths:
            candidates.append({"bank": name, "note": note,
                               "confidence": 0.55})
    if hint:
        hinted = [c for c in candidates if hint in c["bank"].lower()]
        if hinted:
            candidates = [{**hinted[0], "confidence": 0.8}]
        else:
            candidates = [{"bank": bank_hint,
                           "note": "hint klien (panjang tidak cocok tabel)",
                           "confidence": 0.4}]
        ambiguous = False
    else:
        ambiguous = len(candidates) != 1
    return {
        "kind": "account",
        "digits": len(num),
        "account_masked": mask_account(num),
        "candidates": candidates[:6],
        "ambiguous": ambiguous,
        "mapping_note": ("identifikasi bank dari nomor TIDAK deterministik "
                         "penuh — kandidat diurutkan dari panjang "
                         "terdokumentasi; konfirmasi via bank/struk/bukti "
                         "transfer klien"),
        "identity_resolution": ("TIDAK dilakukan — data nasabah hanya bisa "
                                "dibuka bank lewat prosedur resmi "
                                "(pengaduan + kepolisian)"),
    }


# ------------------------------------------------------------- dossier
def render_fraud_dossier(phone: dict | None, account: dict | None,
                         case_note: str = "") -> str:
    lines = [
        "# Dossier Pengaduan Penipuan (fraud-intel, pasif)", "",
        "> Diproduksi Cyphron untuk KORBAN yang melapor. Semua identitas "
        "teredaksi. Cyphron TIDAK melakukan resolusi identitas orang — "
        "identitas pelaku hanya bisa dibuka operator/bank/penegak hukum "
        "lewat prosedur resmi.", "",
        "## 1. Identifikator (teredaksi)", "",
    ]
    if phone:
        lines.append(f"- Nomor HP: `{phone['e164_masked']}` "
                     f"(prefix {phone['prefix']})")
        if phone["candidates"]:
            op = phone["candidates"][0]
            lines.append(f"- Operator (kandidat): **{op['operator']}** "
                         f"(confidence {op['confidence']:.0%}) — "
                         f"{phone['mapping_note']}")
        else:
            lines.append("- Operator: AMBIGU — tidak dipetakan")
    if account:
        lines.append(f"- Nomor rekening: `{account['account_masked']}` "
                     f"({account['digits']} digit)")
        if account["candidates"]:
            lines.append("- Kandidat bank: " + "; ".join(
                f"{c['bank']} ({c['confidence']:.0%})" for c in
                account["candidates"][:3]) + " — " + account["mapping_note"])
        else:
            lines.append("- Bank: AMBIGU — butuh info tambahan dari klien "
                         "(bank penerima tertera di bukti transfer)")
    if case_note:
        lines.append(f"- Catatan kasus: {case_note}")
    lines += ["", "## 2. Langkah resmi (urutan yang benar)", "",
              "1. **CekRekening.id** (Kominfo/BSSN): laporkan nomor "
              "rekening pelaku — cek juga apakah rekening sudah pernah "
              "dilaporkan orang lain (status 'Awas Penipuan').",
              "2. **Bank penerima**: ajukan pembekuan/pengaduan ke bank "
              "kandidat dengan bukti transfer (fotokopi bukti + kronologi); "
              "sebut nomor rekening lengkap HANYA ke bank, tidak ke publik.",
              "3. **OJK 157**: lapor layanan keuangan bermasalah / kanal "
              "kontak pelaku.",
              "4. **Polri Subdit Tipid Siber**: pengaduan resmi (daring/"
              "kantor) — lampirkan dossier ini; kepolisian yang meminta "
              "data identitas pelanggan ke operator/bank.",
              "5. **Operator telekomunikasi** (via kepolisian atau kanal "
              "aduan): blokir/pencabutan nomor pelaku.", "",
              "## 3. Checklist bukti (kumpulkan klien)", "",
              "- Bukti transfer/rek koran (tunjukkan rekening tujuan penuh "
              "— untuk berkas resmi, bukan publik)",
              "- Screenshot percakapan/DM utuh (dengan timestamp)",
              "- Link/konten yang diterima korban (jangan diklik ulang; "
              "cukup simpan)",
              "- Kronologi waktu (jam kejadian, zona waktu)", "",
              "## 4. Yang TIDAK dilakukan Cyphron", "",
              "- Resolusi identitas (nama/alamat/KTP) dari nomor/rekening — "
              "hanya operator/bank/penegak hukum yang berwenang.",
              "- Mengakses atau memanfaatkan data kebocoran (SIM registration/"
              "KTP) — ilegal (UU PDP, UU ITE).",
              "- Menghubungi/mengintimidasi pelaku secara langsung.",
              "", "## 5. Template ringkas pengaduan", "",
              "```",
              "Saya [NAMA], korban penipuan daring pada [TANGGAL].",
              "Pelaku menerima dana via rekening [BANK, NO REK] tercatat",
              "atas nama [SESUI STRUK] dan dapat dihubungi di [NOMOR].",
              "Bukti terlampir (transfer + percakapan). Mohon tindakan",
              "pembekuan/pemeriksaan sesuai prosedur.",
              "```", ""]
    return "\n".join(lines)


def build_fraud_case(phone_raw: str | None = None,
                     account_raw: str | None = None,
                     bank_hint: str | None = None,
                     case_note: str = "",
                     out_dir: Path | None = None) -> dict:
    phone = analyze_phone(phone_raw) if phone_raw else None
    account = analyze_account(account_raw, bank_hint) if account_raw else None
    md = render_fraud_dossier(phone, account, case_note)
    if out_dir is not None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "FRAUD-DOSSIER.md").write_text(md, encoding="utf-8")
    return {"phone": phone, "account": account, "markdown": md}
