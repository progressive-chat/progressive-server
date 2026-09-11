# Step 135 — "Fix docker-compose trusted_servers env var" (Conduit `8387cea`)

Source: [`timokoesters/conduit@8387cea`](https://github.com/timokoesters/conduit/commit/8387cea) (2021-05-25)

Upstream fixes a `trusted_servers` environment variable in the Docker
Compose files.

## What changed vs step 134

**Nothing in `src/` — this directory was a byte-identical copy.** Docker
packaging only; no source change to translate.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit135 && ./build/tests
```
