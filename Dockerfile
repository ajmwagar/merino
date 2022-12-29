FROM rust:alpine as builder
RUN apk add --no-cache build-base

WORKDIR /app/
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM alpine:3.17
RUN addgroup -S merino && \
    adduser -S -G merino merino && \
    apk add --no-cache tini
USER merino
COPY --from=builder /app/target/release/merino /usr/local/bin/merino
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/merino"]
