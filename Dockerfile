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

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pkgwarden /pkgwarden
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/pkgwarden"]
