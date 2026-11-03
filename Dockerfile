# zainVPN coordinator, plus the Windows installer it hands out. Built and run by
# deploy.sh; run it with --network host so clients' real UDP source addresses
# reach the coordinator (hole punching depends on them).

FROM golang:1.27-alpine AS build
# go.mod may ask for a newer patch release than the image ships.
ENV GOTOOLCHAIN=auto CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/zainvpn-server ./cmd/zainvpn-server
# The Windows client, cross-compiled for the installer below.
RUN GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/win/zainvpn.exe ./cmd/zainvpn \
 && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=${VERSION}" -o /out/win/zainvpn-app.exe ./cmd/zainvpn-app \
 && cp third_party/wintun/amd64/wintun.dll /out/win/

# Packages the Windows installer with NSIS, which runs natively on Linux.
FROM debian:trixie-slim AS installer
RUN apt-get update \
 && apt-get install -y --no-install-recommends nsis \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY installer/ installer/
COPY third_party/wintun/LICENSE.txt third_party/wintun/
COPY --from=build /out/win/ build/
# x.y.z; the coordinator address friends' installers start with.
ARG INSTALLER_VERSION=0.0.0
ARG INSTALLER_SERVER=
RUN mkdir -p dist \
 && makensis -V2 "-DVERSION=${INSTALLER_VERSION}" "-DSERVER=${INSTALLER_SERVER}" installer/zainvpn.nsi

FROM alpine:3.22
RUN addgroup -S -g 10001 zainvpn \
 && adduser -S -D -H -u 10001 -G zainvpn -h /data zainvpn \
 && mkdir -p /data \
 && chown zainvpn:zainvpn /data
COPY --from=build /out/zainvpn-server /usr/local/bin/zainvpn-server
COPY --from=installer /src/dist/zainVPN-Setup.exe /usr/share/zainvpn/zainVPN-Setup.exe
ENV ZAINVPN_STATE=/data/state.json \
    ZAINVPN_LISTEN=:29814 \
    ZAINVPN_HTTP=:21958 \
    ZAINVPN_BUNDLED_INSTALLER=/usr/share/zainvpn/zainVPN-Setup.exe
VOLUME ["/data"]
USER zainvpn
EXPOSE 29814/tcp 29814/udp 21958/tcp
# Probes the dashboard port from ZAINVPN_HTTP (busybox wget); passes when the dashboard is turned off.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD addr="${ZAINVPN_HTTP-:21958}"; case "$addr" in ""|off) exit 0;; esac; wget -q -T 3 -O /dev/null "http://127.0.0.1:${addr##*:}/healthz" || exit 1
ENTRYPOINT ["/usr/local/bin/zainvpn-server"]
