# Step 157 — "improvement: change federation_enabled to federation_disabled" (Conduit `85364a9`)

Source: [`timokoesters/conduit@85364a9`](https://github.com/timokoesters/conduit/commit/85364a9) (2021-01-01)

Upstream renames the federation config flag (inverting its default).

## What changed vs step 156

**Nothing in `src/` — this directory was a byte-identical copy.** This port
has no federation toggle (federation is always on), so a config-key rename
has nothing to translate.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit157 && ./build/tests
```
