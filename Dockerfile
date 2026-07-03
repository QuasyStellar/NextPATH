FROM golang:1.22-alpine AS go-builder
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download
COPY internal/ ./internal/
COPY cmd/ ./cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o nextpath-engine ./cmd/nextpath-engine/main.go

FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && mkdir -p /etc/apt/keyrings \
    && curl -fL https://pkg.labs.nic.cz/gpg -o /etc/apt/keyrings/cznic-labs-pkg.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver bookworm main" > /etc/apt/sources.list.d/cznic-labs-knot-resolver.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    knot-resolver \
    knot-resolver-module-http \
    nftables \
    ethtool \
    iproute2 \
    supervisor \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/nextpath

COPY --from=go-builder /build/nextpath-engine /usr/local/bin/
COPY config/ ./config/
COPY lists/ ./lists/
COPY entrypoint.sh /usr/local/bin/
COPY config/kres_modules/ /usr/lib/knot-resolver/kres_modules/

RUN mkdir -p /usr/src/nextpath/defaults && cp -r lists /usr/src/nextpath/defaults/

RUN chmod +x /usr/local/bin/entrypoint.sh && mkdir -p /var/cache/knot-resolver

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
