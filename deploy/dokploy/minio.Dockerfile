FROM golang:1.25.8-alpine AS build

RUN apk add --no-cache git ca-certificates
WORKDIR /src
RUN git init . \
    && git remote add origin https://github.com/minio/minio.git \
    && git fetch --depth=1 origin 9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = 9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a

ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 MINIO_RELEASE=RELEASE
RUN go build -p 2 -trimpath \
    -ldflags="$(go run buildscripts/gen-ldflags.go 2025-10-15T17:29:55Z)" \
    -o /out/minio .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates curl tzdata
COPY --from=build /out/minio /usr/local/bin/minio
COPY --from=build /src/LICENSE /licenses/minio/LICENSE
LABEL org.opencontainers.image.source="https://github.com/minio/minio" \
      org.opencontainers.image.revision="9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a" \
      org.opencontainers.image.version="RELEASE.2025-10-15T17-29-55Z" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
EXPOSE 9000 9001
ENTRYPOINT ["minio"]
CMD ["server", "/data", "--console-address", ":9001"]
