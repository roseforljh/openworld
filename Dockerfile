# Build stage
FROM rust:1.82-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && \
    strip target/release/openworld

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates iptables ip6tables && \
    adduser -D -h /etc/openworld openworld

COPY --from=builder /build/target/release/openworld /usr/local/bin/openworld

RUN mkdir -p /etc/openworld /var/log/openworld && \
    chown -R openworld:openworld /etc/openworld /var/log/openworld

USER openworld
WORKDIR /etc/openworld

EXPOSE 1080 1081 7890

ENTRYPOINT ["openworld"]
CMD ["/etc/openworld/config.yaml"]

HEALTHCHECK --interval=30s --timeout=5s \
    CMD wget -q --spider http://127.0.0.1:9090 || exit 1

LABEL maintainer="OpenWorld Team" \
      description="OpenWorld Proxy Kernel" \
      version="0.1.0"
