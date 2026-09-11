# Step 133 — "fix: logs for ruma crate" (Conduit `57ecd81`)

Source: [`timokoesters/conduit@57ecd81`](https://github.com/timokoesters/conduit/commit/57ecd81) (2021-05-24)

Upstream adjusts the log filter so the `ruma` crate's logs are visible.

## What changed vs step 132

**Nothing in `src/` — this directory was a byte-identical copy.** Logging
configuration only; no behavior change to translate.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit133 && ./build/tests
```
