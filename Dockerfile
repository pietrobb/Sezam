# Images pinned by digest (INV-10, review 8bc70f7 M9); Dependabot moves tag and digest together.

# The team log's rules are the Rust core's (docs/CORE_UNIFICATION.md): its
# Python binding, built from the sources and lock files in this repository.
FROM rust:1.94.1@sha256:652612f07bfbbdfa3af34761c1e435094c00dde4a98036132fca28c7bb2b165c AS core
WORKDIR /src
COPY core /src/core
RUN cargo build --release --locked --manifest-path core/py/Cargo.toml \
    && cp core/py/target/release/libsezam_sync_core.so /sezam_sync_core.abi3.so

FROM python:3.11.18-slim-bookworm@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system sezam \
    && useradd --system --gid sezam --home-dir /app sezam \
    && mkdir -p /app/data \
    && chown sezam:sezam /app/data

COPY server/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt

COPY --from=core /sezam_sync_core.abi3.so /usr/local/lib/python3.11/site-packages/sezam_sync_core.abi3.so
COPY --chown=sezam:sezam server /app/server
# The desktop's door to the core's team log, shared with the server.
COPY --chown=sezam:sezam src/sezam/teamlog.py /app/server/app/teamlog_core.py
# So are the key voucher lists of retired identity keys (goal #443).
COPY --chown=sezam:sezam src/sezam/key_vouchers.py /app/server/app/key_vouchers_core.py
COPY --chown=sezam:sezam web /app/web

USER sezam

EXPOSE 8000

# Client IPs (PIN rate limit, audit) come from X-Forwarded-For, but only when
# the TCP peer is in FORWARDED_ALLOW_IPS (the host reverse proxy); others
# cannot spoof it. Without this every client looks like the proxy.
ENV FORWARDED_ALLOW_IPS=127.0.0.1

CMD ["python", "-m", "uvicorn", "server.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--proxy-headers"]
