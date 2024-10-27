# Intended for use within CI, use the normal Dockerfile for local builds

FROM bash:latest as fetcher
ARG TARGETPLATFORM
ARG BUILDPLATFORM

WORKDIR /
COPY ./artifacts ./artifacts

RUN bash -l -c 'case $TARGETPLATFORM in \

    "linux/amd64") \
        mv ./artifacts/x86_64-unknown-linux-musl/gbe-proxy-server / \
        ;; \

    "linux/arm64") \
        mv ./artifacts/aarch64-unknown-linux-gnu/gbe-proxy-server / \
        ;; \
    esac'

FROM alpine:3.18.2

COPY --from=fetcher /gbe-proxy-server /

EXPOSE 5000/udp

CMD ["./gbe-proxy-server"]