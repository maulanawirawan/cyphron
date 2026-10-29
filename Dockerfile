# Dockerfile produk v2 — core binary + skill python dalam image ramping.
# Audit 2026-10 (P1.F):
#   - base image dipin per-digest (dulu tag mengambang + komentar "pinned")
#   - assets/ ikut disalin (skill intel butuh kev.json & kawan-kawan)
#   - tooling laporan tersedia: typst (linux, ARG-pinned) + PyMuPDF
#     (validasi render report_pdf.py) — dulu report selalu gagal di image
# Build:  docker build -t cyphron:local .
# Jalankan:
#   docker run --rm -p 8900:8900 -v %cd%/findings:/app/findings cyphron:local serve
#   docker run --rm cyphron:local scan --domain contoh.id --report
# Catatan: build image belum diverifikasi ulang sejak perubahan audit ini —
# jalankan smoke sebelum rilis:
#   docker run --rm cyphron:local info
#   docker run --rm cyphron:local scan --domain contoh.id --report

FROM rust:1-slim@sha256:b8e062b1c3a80183df83d9ba187cadd2b5ab84bc78d453dbfeb2fccd5f982247 AS build
WORKDIR /build
COPY core-rs ./core-rs
RUN cargo build --release --manifest-path core-rs/Cargo.toml

FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
# TYPST_VERSION: rilis resmi typst (cek: github.com/typst/typst/releases)
ARG TYPST_VERSION=0.13.1
RUN useradd -m appuser
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "pymupdf==1.24.14" \
    && curl -fsSL "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-x86_64-unknown-linux-musl.tar.xz" \
       -o /tmp/typst.tar.xz \
    && tar -xJf /tmp/typst.tar.xz -C /tmp \
    && install -m 0755 "/tmp/typst-x86_64-unknown-linux-musl/typst" /usr/local/bin/typst \
    && rm -rf /tmp/typst.tar.xz /tmp/typst-x86_64-unknown-linux-musl \
    && typst --version
COPY --from=build /build/core-rs/target/release/cyphron /usr/local/bin/cyphron
COPY core/findings.py core/findings.py
COPY skills skills
COPY tools tools
COPY assets assets
COPY skills/registry.json skills/registry.json
ENV PYTHONUNBUFFERED=1
EXPOSE 8900
HEALTHCHECK --interval=30s --timeout=5s CMD cyphron info || exit 1
USER appuser
ENTRYPOINT ["cyphron"]
CMD ["info"]
