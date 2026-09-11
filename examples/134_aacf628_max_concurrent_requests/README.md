# Step 134 — "improvement: increase default max concurrent requests" (Conduit `aacf628`)

Source: [`timokoesters/conduit@aacf628`](https://github.com/timokoesters/conduit/commit/aacf628) (2021-05-24)

Upstream raises the default `max_concurrent_requests` TOML value.

## What changed vs step 133

**Nothing in `src/` — this directory was a byte-identical copy.** This port
has no TOML config layer and no concurrent-request limiter, so a default
value for one has nothing to translate.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit134 && ./build/tests
```
