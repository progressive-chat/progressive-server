# Step 158 — "improvement: better default config" (Conduit `3bdaf6e`)

Source: [`timokoesters/conduit@3bdaf6e`](https://github.com/timokoesters/conduit/commit/3bdaf6e) (2021-01-01)

Upstream ships a better default `conduit-example.toml`.

## What changed vs step 157

**Nothing in `src/` — this directory was a byte-identical copy.** Example
config only; this port configures itself via CLI flags and ships no TOML.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit158 && ./build/tests
```
