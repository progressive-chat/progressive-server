# Step 148 — "improvement: filter our room directory" (Conduit `77a23f89`)

Source: [`timokoesters/conduit@77a23f89`](https://github.com/timokoesters/conduit/commit/77a23f89) (2021-06-14)

Upstream filters the room directory by a case-insensitive search term over
name, topic and canonical alias.

## What changed vs step 147

**Nothing in `src/` — this directory was a byte-identical copy.** The change
is implemented in the modern chain as step 804
(`804_77a23f89_search_filters`), with case-insensitive matching over name,
topic and canonical alias.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit148 && ./build/tests
```
