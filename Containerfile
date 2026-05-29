# Containerfile — the build.
#
# This is the only supported build path. `docker build` on a clean checkout
# produces a deployable image with no host-side toolchain required beyond
# docker. Docker (with Compose v2) is the only supported runtime; see §7 of
# PLAN.md and the header of compose.yaml for the rationale.
#
# Stages:
#   1. go-build    — compiles the rookery binary
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
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.25-bookworm AS go-build

ARG TARGETARCH
ARG TARGETOS=linux
ARG GIT_REVISION=dev

WORKDIR /src

# Cache dependencies before copying source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a fully static binary compatible with distroless.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X rookery/internal/web.AssetVersion=${GIT_REVISION}" \
    -o /out/rookery \
    ./cmd/rookery/

# Stage an empty message_dir so the final image carries /var/lib/rookery/messages.
# Docker copies this directory's ownership onto a fresh `messages-data` named
# volume when it is first mounted; without it the volume would be created
# root-owned and the nonroot (65532) container could not write blobs there.
RUN mkdir -p /out/messages

# --------------------------------------------------------------------------- #
# Stage 2: JS build
# --------------------------------------------------------------------------- #
# esbuild bundles only the browser crypto module (web/crypto/).
# partials.js and other hand-written JS ship as-is (web/static/).
# The CSS ships as-is (web/static/).
#
# Node is used *only* here, inside the multi-stage build, so developers never
# need to install Node on their host machines. See §7.
FROM docker.io/library/node:22-bookworm-slim AS js-build

WORKDIR /src/web/crypto

# Install only the declared dependencies — no transitive postinstall scripts.
# --ignore-scripts prevents any lifecycle hooks from running. See P12.
COPY web/crypto/package.json web/crypto/package-lock.json ./
RUN npm ci --ignore-scripts

COPY web/crypto/ ./
RUN node_modules/.bin/esbuild \
    --bundle \
    --minify \
    --format=iife \
    --global-name=RookeryCrypto \
    --outfile=/out/crypto.js \
    index.js

# --------------------------------------------------------------------------- #
# Stage 3: Final distroless image
# --------------------------------------------------------------------------- #
FROM gcr.io/distroless/static-debian12:nonroot AS final

# Binary
COPY --from=go-build /out/rookery /usr/local/bin/rookery

# Message blob directory, owned by the distroless nonroot UID (65532). A fresh
# `messages-data` volume mounted here inherits this ownership, so the nonroot
# process can create blobs and the exports/ subdirectory without any chown.
COPY --from=go-build --chown=65532:65532 /out/messages /var/lib/rookery/messages

# Hand-written static assets (no build step needed — copy the whole directory)
COPY web/static/ /opt/rookery/web/static/

# Bundled JS crypto module (produced by Stage 2). This COPY runs *after* the
# hand-written static assets so that any accidental web/static/crypto.js
# placeholder in the source tree cannot silently shadow the real bundle.
COPY --from=js-build /out/crypto.js /opt/rookery/web/static/crypto.js

EXPOSE 8080 443 25 465 587

# Healthcheck is defined in compose.yaml rather than here, so the compose file
# remains the single source of truth for runtime behaviour. The
# `rookery healthcheck` subcommand (see cmd/rookery/main.go) is what compose
# invokes; the distroless runtime image has no shell or wget/curl, so this
# subcommand is the only viable probe.

ENTRYPOINT ["/usr/local/bin/rookery"]
CMD ["serve"]
