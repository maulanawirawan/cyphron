// Template laporan kategorial Cyphron — Typst.
// Data disuntik dari data.json (dihasilkan tools/report_pdf.py) sehingga
// teks temuan TIDAK pernah diinterpretasi sebagai markup typst.
#let data = json("data.json")
#let sevcolor(sev) = if sev == "critical" { rgb("7f1d1d") } else if sev == "high" { rgb("b91c1c") } else if sev == "medium" { rgb("b45309") } else if sev == "low" { rgb("a16207") } else { rgb("374151") }
#let verdictcolor(v) = if v == -1 { rgb("6b7280") } else if v >= 3 { rgb("166534") } else { rgb("92400e") }

#set page(paper: "a4", margin: (x: 2.2cm, y: 2.2cm),
  numbering: "1", header: context {
    if counter(page).get().first() > 1 [
      #set text(size: 8pt, fill: rgb("6b7280"))
      #data.title #h(1fr) Cyphron — laporan internal · LOCAL-ONLY
    ]
  })
#set text(font: "Libertinus Serif", size: 10pt)
#set par(justify: true)

// ===== COVER =====
#align(center)[
  #v(2cm)
  #text(size: 24pt, weight: "bold")[#data.title]
  #v(0.5cm)
  #text(size: 12pt, fill: rgb("374151"))[#data.subtitle]
  #v(1cm)
  #text(size: 10pt, fill: rgb("6b7280"))[
    Tanggal: #data.date \
    Target: #data.targets.join(", ") \
    Sumber data: #data.sources.join("; ") \
    Total temuan: #data.total_findings (#data.reportable_count reportable L3+, #data.lead_count lead, #data.rejected_count rejected) \
    Permintaan jaringan dalam run (selain DoH): #data.requests
  ]
  #v(1cm)
  #text(size: 9pt, fill: rgb("6b7280"))[
    Dokumen LOCAL-ONLY. Dibuat dari data terverifikasi kontrak
    findings.json — setiap klaim membawa bukti; yang belum terbukti
    dilabeli LEAD (bukan klaim).
  ]
]
#pagebreak()

// ===== RINGKASAN EKSEKUTIF =====
= Ringkasan Eksekutif

#block(width: 100%, fill: rgb("eef2ff"), stroke: (left: 3pt + rgb("1d4ed8")), inset: 9pt, radius: 3pt)[
  #text(size: 9.5pt)[#text(weight: "bold")[Baris bawah: ]#data.bottom_line]
]

#data.executive_summary

#v(0.4cm)

#block(width: 100%, fill: luma(248), stroke: (left: 3pt + rgb("1d4ed8")), inset: 9pt, radius: 3pt)[
  #text(size: 10.5pt, weight: "bold")[Cara membaca laporan ini (bahasa sederhana)]
  #v(0.2cm)
  #table(
    columns: (auto, 1fr, auto),
    inset: 5pt,
    align: (left, left, right),
    table.header([*Status*], [*Artinya buat Anda*], [*Jumlah*]),
    ..data.plain_guide.map(g => (table.cell(box(fill: rgb(g.color), radius: 2pt, inset: (x: 5pt, y: 2pt))[
        #text(fill: white, size: 8pt, weight: "bold")[#g.label]
      ]),
      table.cell([#text(size: 9pt)[#g.meaning]]),
      table.cell([#text(weight: "bold")[#g.count]]))).flatten(),
  )
  #text(size: 8.5pt, fill: rgb("6b7280"))[
    Status di atas dipetakan langsung dari tangga bukti L0-L5 (bagian
    Metodologi) — tidak ada penilaian tambahan di luar bukti. Yang
    TERBUKTI boleh langsung ditindak/dilaporkan; yang lain adalah bahan
    kerja, bukan kesimpulan.
  ]
]

#v(0.4cm)
#table(
  columns: 6,
  align: center,
  table.header([*Severity*], [*critical*], [*high*], [*medium*], [*low*], [*info*]),
  table.cell(fill: luma(245))[*Jumlah*],
  ..data.by_severity.map(n => table.cell([#n])),
)

#v(0.4cm)
#table(
  columns: 5,
  align: center,
  table.header([*Verdict*], [*L2+ reproduksi*], [*L1 dugaan*], [*L0 bersih*], [*ditolak*]),
  table.cell(fill: luma(245))[*Jumlah*],
  ..(data.verdict_counts.l2plus, data.verdict_counts.l1, data.verdict_counts.l0, data.verdict_counts.rejected).map(n => table.cell([#n])),
)
#text(size: 9pt, fill: rgb("6b7280"))[
  Cakupan efektif: #data.coverage.note#if data.coverage.failed_tools.len() > 0 [ — gagal penuh: #data.coverage.failed_tools.join(", ") (lihat section fail-closed) ]
]

#if data.top_leads.len() > 0 [
  == Paling Perlu Perhatian

  #for tl in data.top_leads [
    #block(width: 100%, stroke: (left: 2.5pt + rgb("b45309")), inset: (left: 8pt, y: 5pt))[
      #text(weight: "bold", size: 10.5pt)[#tl.title]
      #box(fill: rgb("92400e"), radius: 2pt, inset: (x: 4pt, y: 1pt))[
        #text(fill: white, size: 7.5pt, weight: "bold")[#tl.verdict_tag]
      ]
      #text(size: 9pt)[#tl.why#if tl.why.len() >= 200 […]]
    ]
    #v(0.25cm)
  ]
]

#if data.egress != none [
  #block(width: 100%, fill: luma(245), inset: 8pt, radius: 3pt)[
    #text(size: 9pt, weight: "bold")[Kesehatan egress saat run]
    #text(size: 9pt)[
      #for c in data.egress.checks [#c.check: #if c.ok [OK] else [BLOKIR] (#c.detail) · ]
      #data.egress.note
    ]
  ]
]

#if data.threat_model != none [
  #block(width: 100%, fill: luma(245), inset: 8pt, radius: 3pt)[
    #text(size: 9pt, weight: "bold")[Threat model program (konteks pemilik)]
    #text(size: 9pt)[
      #data.threat_model.title
      #if data.threat_model.sections.len() > 0 [
        — bagian: #for s in data.threat_model.sections [#s · ]
      ]
      (Sumber: #data.threat_model.path, sha256 #data.threat_model.sha256.        Konteks triage dari pemilik program — tidak mengubah klasifikasi        temuan di laporan ini.)
    ]
  ]
]

= Metodologi & Verdict Ladder

Setiap temuan diberi tingkat bukti (verdict ladder). Hanya L3+
(_deterministically verified_ ke atas) yang dilaporkan sebagai klaim;
L0-L2 adalah _lead_ (petunjuk yang belum terbukti), L-x adalah temuan
yang tertolak (false positive terbukti). Disiplin ini menekan false
positive ke nol pada laporan akhir.

#table(
  columns: (auto, auto, 1fr),
  inset: 6pt,
  table.header([*Level*], [*Nama*], [*Arti*]),
  ..data.ladder.map(l => (table.cell([#l.level]), table.cell([#l.name]), table.cell([#l.desc]))).flatten(),
)

= Temuan per Kategori

#for cat in data.categories [
  == Kategori: #cat.name (#cat.count temuan)

  #for f in cat.findings [
    #block(width: 100%, stroke: (left: 2.5pt + sevcolor(f.severity)), inset: (left: 8pt, y: 6pt))[
      #text(weight: "bold", size: 11pt)[#f.title]
      #h(1fr)
      #box(fill: sevcolor(f.severity), radius: 2pt, inset: (x: 5pt, y: 2pt))[
        #text(fill: white, size: 8pt, weight: "bold")[#upper(f.severity)]
      ]
      #box(fill: verdictcolor(f.verdict), radius: 2pt, inset: (x: 5pt, y: 2pt))[
        #text(fill: white, size: 8pt, weight: "bold")[#f.verdict_tag]
      ]
      #box(fill: rgb(f.plain_color), stroke: 0.5pt + luma(255), radius: 2pt, inset: (x: 5pt, y: 2pt))[
        #text(fill: white, size: 8pt, weight: "bold")[#f.plain_label]
      ]
      #if f.family_quorum != none [
        #box(fill: rgb("1d4ed8"), radius: 2pt, inset: (x: 5pt, y: 2pt))[
          #text(fill: white, size: 8pt, weight: "bold")[FQ ×#f.family_quorum]
        ]
      ]

      #text(size: 9.5pt)[
        #f.description
      ]

      #text(size: 9pt, fill: rgb("1f2937"))[
        #text(weight: "bold")[#f.plain_why]
      ]

      #if f.recommendation != "" [
        #text(size: 9pt)[*Rekomendasi:* #f.recommendation]
      ]
      #text(size: 8pt, fill: rgb("6b7280"))[
        Target: #f.target \
        Bukti: #f.evidence_kind #if f.cwe != none [(#f.cwe)] \
        Kelas safety: #f.safety_class · Confidence: #f.confidence · ID: #f.id \
        #if f.family_quorum != none [
          Family quorum: ×#f.family_quorum (#f.family_sources.join(", "))
        ]
      ]
    ]
    #v(0.3cm)
  ]
]

= Tidak Dapat Dinilai (fail-closed)

#if data.unconfirmed.len() > 0 [
  Ini bagian status _TIDAK BISA DINILAI_ (lihat kotak "Cara membaca").
  Baris berikut adalah kegagalan pengumpulan data (jaringan/timeout)
  atau sumber yang dilewati kebijakan opt-in — _bukan temuan_, dan
  sengaja dicatat agar tidak ada yang disembunyikan. Ulangi saat
  jaringan sehat untuk cakupan penuh.

  #for u in data.unconfirmed [
    #block(width: 100%, stroke: (left: 2pt + rgb("9ca3af")), inset: (left: 8pt, y: 4pt))[
      #text(size: 9.5pt)[#u.title #h(1fr) #u.tool]
      #text(size: 8.5pt, fill: rgb("6b7280"))[
        #u.description
      ]
    ]
  ]
] else [
  Tidak ada baris gagal — seluruh skill selesai tanpa hambatan.
]

// ===== APPENDIX A — PRECISION =====
#pagebreak()
= Appendix A — Metrik Presisi per Tool

Presisi dilaporkan per tool: berapa banyak temuan yang mencapai bukti
reportable (L3+) dibanding total temuan yang dihasilkan tool tersebut.
Temuan yang tertolak (L-x) dicatat terpisah sebagai bukti disiplin
zero-FP.

#table(
  columns: 8,
  align: (left, center, center, center, center, center, center, center),
  table.header([*Tool*], [*Total*], [*L3+ (reportable)*], [*Lead (L0-L2)*], [*L-x*], [*Rasio L3+*], [*Request*], [*Temuan/Req*]),
  ..data.precision.map(t => (table.cell([#t.tool]), table.cell([#t.total]), table.cell([#t.reportable]), table.cell([#t.leads]), table.cell([#t.rejected]), table.cell([#t.ratio]), table.cell([#t.requests]), table.cell([#t.findings_per_request]))).flatten(),
)

= Appendix A2 — Metrik Kepadatan Run

Kepadatan mengukur efisiensi pipa: berapa banyak temuan yang dihasilkan
per unit biaya — request jaringan ke target dan detik waktu run. Angka
ini _bukan_ ukuran kualitas temuan; ia membantu membandingkan konfigurasi
run (mis. dengan/tanpa mode bukti) secara adil.

#table(
  columns: (auto, auto),
  align: (left, right),
  table.header([*Metrik*], [*Nilai*]),
  [Total temuan], [#data.density.total_findings],
  [Request ke target], [#data.density.requests],
  [Durasi run (detik)], [#data.density.elapsed_s_display],
  [Temuan / request], [#data.density.fpr_display],
  [Temuan / detik], [#data.density.fps_display],
  [Reportable (L3+) / request], [#data.density.rpr_display],
)

= Appendix B — Pemetaan Compliance (Indikatif)

Pemetaan indikatif per CWE terhadap kerangka kepatuhan umum. Bukan
penilaian audit — hanya titik awal percakapan.

#table(
  columns: 4,
  align: (left, left, left, left),
  table.header([*CWE*], [*PCI DSS 4.0*], [*SOC 2*], [*ISO 27001*]),
  ..data.compliance.map(c => (table.cell([#c.cwe]), table.cell([#c.pci]), table.cell([#c.soc2]), table.cell([#c.iso]))).flatten(),
)

#if data.delta != none [
  = Appendix C — Retest Delta (Perubahan Sejak Assessment Sebelumnya)

  Delta dihitung dari ID temuan deterministik (sha256
  tool|title|target|file|param). Perubahan judul teks akan dihitung
  sebagai temuan berbeda — catatan metodologi ini disertakan agar
  pembaca tidak salah tafsir.

  #table(
    columns: (auto, auto),
    align: (left, right),
    table.header([*Status*], [*Jumlah*]),
    [Masih ada (old n new)], [#data.delta.persist],
    [Terbukti diperbaiki (hanya di run lama)], [#data.delta.fixed],
    [Baru muncul (hanya di run baru)], [#data.delta.new],
  )

  #if data.delta.fixed_items.len() > 0 [
    === Terbukti diperbaiki
    #for t in data.delta.fixed_items [ - #t ]
  ]
  #if data.delta.new_items.len() > 0 [
    === Baru muncul
    #for t in data.delta.new_items [ - #t ]
  ]
]

#if data.class_history.len() > 0 [
  #pagebreak()
  = Appendix D — Riwayat Kelas (Learning Loop)

  Statistik hasil triage nyata per kelas temuan (dari outcomes
  pembelajaran, read-only). Kelas dengan riwayat ditolak _duplikat_
  menuntut novelty-check sebelum lapor; kelas dengan riwayat ditolak
  _dampak_ wajib menyertai narrative dampak + bukti terukur. Tabel ini
  konteks penyusunan laporan — bukan bagian dari klaim temuan.

  #table(
    columns: 6,
    align: (left, center, center, center, center, center),
    table.header([*Kelas*], [*Seen*], [*Diterima (Fixing)*], [*Ditolak Duplikat*], [*Ditolak Dampak*], [*Rasio*]),
    ..data.class_history.map(c => (table.cell([#c.finding_class]), table.cell([#c.seen]), table.cell([#c.accepted_fixing]), table.cell([#c.rejected_duplicate]), table.cell([#c.rejected_impact]), table.cell([#c.acceptance_rate_display]))).flatten(),
  )
]
