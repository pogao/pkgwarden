# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X github.com/pogao/pkgwarden/internal/telemetry.version=${VERSION}" -o /out/pkgwarden ./cmd/pkgwarden

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/pkgwarden /pkgwarden
EXPOSE 8080
# A numeric user lets Kubernetes runAsNonRoot verify that it is not root.
USER 65532:65532
ENTRYPOINT ["/pkgwarden"]
