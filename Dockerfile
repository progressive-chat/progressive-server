FROM alpine:edge AS builder

RUN apk add --no-cache \
    cmake ninja g++ boost-dev openssl-dev sqlite-dev \
    nlohmann-json samurai

COPY . /src
WORKDIR /src

RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DPROGRESSIVE_BUILD_TESTS=OFF && \
    cmake --build build -j$(nproc) && \
    strip build/src/progressive-server

FROM alpine:edge

RUN apk add --no-cache \
    boost-url boost-json libstdc++ sqlite-libs openssl && \
    addgroup -S progressive && adduser -S progressive -G progressive

COPY --from=builder /src/build/src/progressive-server /usr/local/bin/
COPY --from=builder /src/src/progressive/storage/schema /usr/share/progressive-server/storage/schema

EXPOSE 8008 8448

USER progressive
ENTRYPOINT ["/usr/local/bin/progressive-server"]
CMD ["-c", "/etc/progressive/homeserver.yaml"]
