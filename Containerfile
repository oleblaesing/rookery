FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.25-bookworm AS go-build

ARG TARGETARCH
ARG TARGETOS=linux
ARG GIT_REVISION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X rookery/internal/web.AssetVersion=${GIT_REVISION}" \
    -o /out/rookery \
    ./cmd/rookery/

FROM docker.io/library/node:22-bookworm-slim AS js-build

WORKDIR /src/web/crypto

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

FROM gcr.io/distroless/static-debian12 AS final

COPY --from=go-build /out/rookery /usr/local/bin/rookery
COPY web/static/ /opt/rookery/web/static/
COPY --from=js-build /out/crypto.js /opt/rookery/web/static/crypto.js

EXPOSE 8080 25

ENTRYPOINT ["/usr/local/bin/rookery"]
CMD ["serve"]
