FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /janus ./cmd/janus/

FROM alpine:3.21
# python3 powers the optional mitmproxy-style Python filter engine (pyfilter).
RUN apk add --no-cache ca-certificates python3
COPY --from=builder /janus /usr/local/bin/janus

ENTRYPOINT ["janus"]
