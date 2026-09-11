# Step 124 — "fix: add trusted_servers to config and deploy guide" (Conduit `3408d74`)

Source: [`timokoesters/conduit@3408d74`](https://github.com/timokoesters/conduit/commit/3408d74) (2021-05-05)

Upstream documents the `trusted_servers` TOML key and deploy guide entry.

## What changed vs step 123

**Nothing in `src/` — this directory was a byte-identical copy.** Docs and
example-config only; this port has no TOML config layer and no trusted-server
concept, so there is nothing to translate.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit124 && ./build/tests
```
