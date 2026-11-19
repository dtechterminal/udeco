# syntax=docker/dockerfile:1
# udeco: TP-Link Deco units as UniFi APs (docs/deco/README.md).
# Static linux/amd64 binary on distroless; runs as 99:100 (Unraid's
# nobody:users) and keeps everything under the /data volume.

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/udeco ./cmd/udeco

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/udeco /udeco
USER 99:100
VOLUME ["/data"]
ENTRYPOINT ["/udeco"]
CMD ["-config", "/data/udeco.json"]
