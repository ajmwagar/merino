FROM rust:1.63-alpine3.16 as builder

RUN apk add --no-cache git musl-dev
RUN git clone https://github.com/ajmwagar/merino \
  && cd merino \
  && cargo install --path .

FROM alpine:3.16

RUN apk update && apk upgrade
COPY --from=builder /usr/local/cargo/bin/merino /usr/local/bin/merino

EXPOSE 1080
ENTRYPOINT ["merino"]
