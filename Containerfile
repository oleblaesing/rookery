# Containerfile — the build.
#
# This is the only supported build path. `docker build` on a clean checkout
# produces a deployable image with no host-side toolchain required beyond
# docker. Docker (with Compose v2) is the only supported runtime; see §7 of
# PLAN.md and the header of compose.yaml for the rationale.
#
# Stages:
#   1. go-build    — compiles the rookery-server binary
#   2. js-build    — bundles the browser crypto module via esbuild
#                    (partials.js ships hand-written; no bundler needed for it)
#   3. final       — distroless image with the binary + static assets
#
# FROM references are fully qualified (e.g. docker.io/library/golang rather
# than golang) as a small piece of supply-chain hygiene.

# --------------------------------------------------------------------------- #
# Stage 1: Go build
# --------------------------------------------------------------------------- #
# BuildKit (docker buildx) automatically provides BUILDPLATFORM and
# TARGETARCH. We default to the build host's architecture when neither is set,
# so a plain `docker build` on amd64 or arm64 still works.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.23-bookworm AS go-build

ARG TARGETARCH
ARG TARGETOS=linux

WORKDIR /src

# Cache dependencies before copying source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a fully static binary compatible with distroless.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
    -o /out/rookery-server \
    ./cmd/rookery-server/

# --------------------------------------------------------------------------- #
# Stage 2: JS build
# --------------------------------------------------------------------------- #
# esbuild bundles only the browser crypto module (web/crypto/).
# partials.js is hand-written and ships as-is (web/partials/).
# The CSS ships as-is (web/static/).
#
# Node is used *only* here, inside the multi-stage build, so developers never
# need to install Node on their host machines. See §7.
FROM docker.io/library/node:22-bookworm-slim AS js-build

WORKDIR /src/web/crypto

# Install only esbuild — no other npm packages.
# --ignore-scripts prevents any postinstall hooks from running. See P12.
COPY web/crypto/package.json web/crypto/package-lock.json ./
RUN npm ci --ignore-scripts

COPY web/crypto/ ./
RUN node_modules/.bin/esbuild \
    --bundle \
    --minify \
    --outfile=/out/crypto.js \
    index.js

# --------------------------------------------------------------------------- #
# Stage 3: Final distroless image
# --------------------------------------------------------------------------- #
FROM gcr.io/distroless/static-debian12:nonroot AS final

# Binary
COPY --from=go-build /out/rookery-server /usr/local/bin/rookery-server

# Static web assets
COPY --from=js-build /out/crypto.js          /opt/rookery/web/static/crypto.js
# Phase 0 ships the binary + crypto bundle only. The web/static, web/partials,
# internal/web/templates, and scripts/ trees land in Phase 1 onward; their
# COPY directives are added then.

EXPOSE 80 443 25 465 587

# Healthcheck is defined in compose.yaml rather than here, so the compose file
# remains the single source of truth for runtime behaviour. The
# `rookery-server healthcheck` subcommand (see cmd/rookery-server/main.go) is
# what compose invokes; the distroless runtime image has no shell or
# wget/curl, so this subcommand is the only viable probe.

ENTRYPOINT ["/usr/local/bin/rookery-server"]
