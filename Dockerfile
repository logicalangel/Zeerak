# syntax=docker/dockerfile:1.7

# --- build stage ---
FROM golang:1.26-alpine AS build
WORKDIR /src
# Cache deps separately from sources.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0-docker
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/zeerak-server ./cmd/zeerak-server

# --- runtime stage ---
# Alpine has nftables in its repos; the binary shells out to `nft`.
FROM alpine:3.20
RUN apk add --no-cache nftables iproute2 ca-certificates \
 && mkdir -p /etc/zeerak /var/lib/zeerak /run/zeerak

COPY --from=build /out/zeerak-server /usr/local/bin/zeerak-server
COPY deploy/examples/zeerak.yaml /etc/zeerak/zeerak.yaml

# HTTP API on loopback by default — expose explicitly so `docker run -p` works.
EXPOSE 7878
VOLUME ["/etc/zeerak", "/var/lib/zeerak"]

# nft writes need CAP_NET_ADMIN; provide that with `--cap-add=NET_ADMIN`.
# The container also needs its own net namespace (default) so it doesn't
# stomp on the host firewall.
ENTRYPOINT ["/usr/local/bin/zeerak-server"]
CMD ["--listen", "0.0.0.0:7878", "--config", "/etc/zeerak/zeerak.yaml"]
