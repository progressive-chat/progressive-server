# Step 160 — "Getting capabilities requires authentication" (Conduit `dcb5e59`)

Source: [`timokoesters/conduit@dcb5e59`](https://github.com/timokoesters/conduit/commit/dcb5e59) (2021-07-11)

Upstream requires authentication for `GET /capabilities`.

## What changed vs step 159

**Nothing in `src/` — this directory was a byte-identical copy.** The change
is implemented in the modern chain as step 811
(`811_dcb5e590_capabilities_auth`), whose `GET /capabilities` route returns
401 without a token and the room-versions capability with one.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit160b && ./build/tests
```
