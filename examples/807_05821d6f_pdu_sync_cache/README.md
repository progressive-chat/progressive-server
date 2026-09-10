# Step 807 — "improvement: pdu cache, /sync cache" (Conduit `05821d6f`)

Source: [`timokoesters/conduit@05821d6f`](https://github.com/timokoesters/conduit/commit/05821d6f) (2021-06-30)

Upstream adds an in-memory PDU cache so repeated event lookups (notably the
ones `/sync` performs per room) don't hit the database every time.

## What changed vs step 805

(Based on step 805: step 806, the `/search`-for-multiple-rooms translation,
does not build and is skipped as a base.)

| Rust change | C++ translation |
|---|---|
| **PDU cache for `get_pdu`** | **Implemented** — new `database::LRUCache<Key, Value>` template (`src/database.hpp`), a `mutable pdu_cache` (capacity 1000) on `Database`, populated on miss inside `Data::pdu_get()` (`src/data.cpp`) |
| **`/sync` cache** | **Covered by the same cache** — sync-time event lookups go through `pdu_get()`, so repeated syncs are served from memory |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit807
```
