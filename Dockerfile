# Dockerfile produk v2 — core binary + skill python dalam image ramping.
# Build:  docker build -t cyphron:local .
# Jalankan:
#   docker run --rm -p 8900:8900 -v %cd%/findings:/app/findings cyphron:local serve
#   docker run --rm cyphron:local scan --domain contoh.id --report

FROM rust:1-slim AS build # pinned 2026-10
WORKDIR /build
COPY core-rs ./core-rs
RUN cargo build --release --manifest-path core-rs/Cargo.toml

FROM python:3.12-slim # pinned 2026-10
RUN useradd -m appuser
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/core-rs/target/release/cyphron /usr/local/bin/cyphron
COPY core/findings.py core/findings.py
COPY skills skills
COPY tools tools
COPY skills/registry.json skills/registry.json
ENV PYTHONUNBUFFERED=1
EXPOSE 8900
HEALTHCHECK --interval=30s --timeout=5s CMD cyphron info || exit 1
USER appuser
ENTRYPOINT ["cyphron"]
CMD ["info"]
