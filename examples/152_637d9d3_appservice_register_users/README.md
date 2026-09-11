# Step 152 — "Always allow appservices to register new users" (Conduit `637d9d3`)

Source: [`timokoesters/conduit@637d9d3`](https://github.com/timokoesters/conduit/commit/637d9d3) (2021-06-19)

Upstream lets appservices register users even when public registration is
disabled (one-line gate bypass).

## What changed vs step 151

**Nothing in `src/` — this directory was a byte-identical copy.** This port
has no registration gate at all — registration is always open — so there is
no gate to bypass.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit152a && ./build/tests
```
