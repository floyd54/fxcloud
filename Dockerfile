# fxcloud - build the image and run it:
#
#   docker build -t fxcloud .
#   docker run -d --name fxcloud \
#     -p 8080:8080 \
#     -v fxcloud-data:/data \
#     fxcloud
#
# Then open http://localhost:8080 and register - the first account becomes
# the admin. Behind a reverse proxy add the two HTTPS knobs:
#
#   -e FXCLOUD_ORIGIN=https://cloud.example.com \  # passkeys see this URL
#   -e FXCLOUD_SECURE_COOKIE=1                     # Secure cookie attribute
#
# The data (database + file blobs) lives in the /data volume, so updating is
# `docker build` again and re-running the container with the same volume.
# The built-in HEALTHCHECK polls /login on the configured port.

# ---- build: the static musl binary ----------------------------------------
FROM rust:alpine AS build
# build-base: the C compiler rusqlite's bundled SQLite needs to build.
RUN apk add --no-cache build-base
WORKDIR /src

# Warm the dependency layer first: while src/ stays unchanged only fxcloud
# itself is rebuilt, the crates below are cached.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# The frontend and the migrations are embedded into the binary (RustEmbed),
# so they only have to exist by the time fxcloud itself is compiled.
COPY . .
RUN cargo build --release

# ---- runtime: alpine, the binary, a data directory -------------------------
FROM alpine:3.21
# A system user that owns /data; the container never runs as root.
RUN addgroup -S fxcloud \
    && adduser -S -G fxcloud -h /data fxcloud \
    && mkdir -p /data \
    && chown fxcloud:fxcloud /data
COPY --from=build /src/target/release/fxcloud /usr/local/bin/fxcloud

ENV FXCLOUD_BIND=0.0.0.0 \
    FXCLOUD_PORT=8080 \
    FXCLOUD_DATA=/data \
    RUST_LOG=fxcloud=info
EXPOSE 8080
VOLUME /data
WORKDIR /data
USER fxcloud
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -q -O /dev/null "http://127.0.0.1:${FXCLOUD_PORT:-8080}/login" || exit 1
ENTRYPOINT ["/usr/local/bin/fxcloud"]
