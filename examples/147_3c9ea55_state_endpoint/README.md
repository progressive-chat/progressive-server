# Step 147 — "feat: /state" (Conduit `3c9ea55`)

Source: [`timokoesters/conduit@3c9ea55`](https://github.com/timokoesters/conduit/commit/3c9ea55) (2021-06-14)

Upstream adds the `GET /rooms/{roomId}/state` endpoints (full room state,
single state event by type/key).

## What changed vs step 146

**Nothing in `src/` — this directory was a byte-identical copy.** The
endpoints are implemented in the modern chain (room state GET/PUT routes
with the state handler), so there is nothing to add here.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit147 && ./build/tests
```
