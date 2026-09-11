# Step 156 — "improvement: better config, better logs" (Conduit `edfd3c1`)

Source: [`timokoesters/conduit@edfd3c1`](https://github.com/timokoesters/conduit/commit/edfd3c1) (2020-12-31)

Upstream tidies configuration handling and log messages.

## What changed vs step 155

**Nothing in `src/` — this directory was a byte-identical copy.** Config /
logging polish with no behavior change to translate (this port configures
itself via CLI flags and has no TOML layer).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit156 && ./build/tests
```
