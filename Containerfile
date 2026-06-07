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

WORKDIR /src

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY client/ ./client/
RUN npm run build

FROM gcr.io/distroless/static-debian12 AS final

COPY --from=go-build /out/rookery /usr/local/bin/rookery
COPY static/ /opt/rookery/web/static/
COPY --from=js-build /src/static/crypto.js /opt/rookery/web/static/crypto.js

EXPOSE 8080 25

ENTRYPOINT ["/usr/local/bin/rookery"]
CMD ["serve"]
