# Step 136 — "fix: state resolution bugs" (Conduit `daa1fc9`)

Source: [`timokoesters/conduit@daa1fc9`](https://github.com/timokoesters/conduit/commit/daa1fc9) (2021-05-27)

Upstream fixes how fork-state events are added to the `auth_cache` during
state resolution (plus a Cargo dependency bump).

## What changed vs step 135

**Nothing in `src/` — this directory was a byte-identical copy.** The fix
targets the `auth_cache` event map, which this port removed (following
upstream `98f1480e`, step 808) in favor of direct `pdu_get()` lookups — so
the buggy code path no longer exists to fix. The Cargo bump is
dependency-only, skipped per project rules.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit136 && ./build/tests
```
