# syntax=docker/dockerfile:1.6
############################
# Build stage
############################
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src

# Faster, repeatable builds
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Bring in the source
COPY . .

# Build args for version info (optional)
ARG VERSION_PATH=github.com/DragonSecurity/drill/internal/version
ARG GIT_COMMIT=unknown
ARG UI_VERSION=container
ARG BUILD_DATE=unknown
ARG TARGETOS TARGETARCH

ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w -X ${VERSION_PATH}.GitCommit=${GIT_COMMIT} -X ${VERSION_PATH}.UIVersion=${UI_VERSION} -X ${VERSION_PATH}.BuildDate=${BUILD_DATE}" \
      -o /out/drill-server ./cmd/drill-server

############################
# Runtime stage
############################
FROM gcr.io/distroless/static:nonroot AS runtime
WORKDIR /app

# Copy the server
COPY --from=build /out/drill-server /usr/local/bin/drill-server

# Ports the server listens on (HTTP and SSH)
EXPOSE 2000 2200

# Run as non-root
USER 65532:65532

# Expect a config at /etc/drill/drill-server.yaml (mount it)
ENTRYPOINT ["/usr/local/bin/drill-server"]
CMD ["-config", "/etc/drill/drill-server.yaml"]
