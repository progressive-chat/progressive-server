# Step 144 — "add migrations" (Conduit `2385bd1`)

Source: [`timokoesters/conduit@2385bd1`](https://github.com/timokoesters/conduit/commit/2385bd1) (2021-06-09)

Upstream adds versioned database migrations (sled schema upgrades).

## What changed vs step 143

**Nothing in `src/` — this directory was a byte-identical copy.** Each step
in this port opens a fresh database with a fixed schema, so there is no
schema to migrate (the single exception — step 127's server-room index
backfill — carries its own version check).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit144 && ./build/tests
```
