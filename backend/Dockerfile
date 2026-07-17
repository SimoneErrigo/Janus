# syntax=docker/dockerfile:1.7

# Janus is pure Go when CGO is disabled. Compile for the requested target on
# the native BuildKit runner instead of running the Go toolchain under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /janus ./cmd/janus/

FROM alpine:3.21
# python3 powers the optional mitmproxy-style Python filter engine (pyfilter).
RUN apk add --no-cache ca-certificates python3
COPY --from=builder /janus /usr/local/bin/janus

ENV API_PORT=9090

ENTRYPOINT ["janus"]
