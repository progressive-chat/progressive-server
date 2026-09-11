# Step 153 — "improvement: better warnings when server is unreachable" (Conduit `fb9bd34`)

Source: [`timokoesters/conduit@fb9bd34`](https://github.com/timokoesters/conduit/commit/fb9bd34) (2020-12-23)

Upstream includes the underlying error in the "could not connect" message.

## What changed vs step 152

**Nothing in `src/` — this directory was a byte-identical copy.** The port's
federation sender already logs the failure reason with each failed request,
so the improved warning is covered.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit153a && ./build/tests
```
