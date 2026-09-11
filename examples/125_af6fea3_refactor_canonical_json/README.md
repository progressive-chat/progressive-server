# Step 125 — "Refactor some canonical JSON code" (Conduit `af6fea3`)

Source: [`timokoesters/conduit@af6fea3`](https://github.com/timokoesters/conduit/commit/af6fea3) (2021-05-08)

Upstream refactors `ruma_wrapper.rs` JSON handling (cleaner `unsigned`
access, restructured UIAA session lookup); no behavior change.

## What changed vs step 124

**Nothing in `src/` — this directory was a byte-identical copy.** Pure Rust
refactor with identical wire behavior; the port's hand-written JSON code has
no corresponding structure to refactor.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit125 && ./build/tests
```
