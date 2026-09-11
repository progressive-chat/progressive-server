# Step 141 — "fix: don't apply push rules for users of other homeservers" (Conduit `e1e529d`)

Source: [`timokoesters/conduit@e1e529d`](https://github.com/timokoesters/conduit/commit/e1e529d) (2021-05-30)

Upstream skips push-rule evaluation for remote users.

## What changed vs step 140

**Nothing in `src/` — this directory was a byte-identical copy.** The change
is implemented in the modern chain as step 802
(`802_e1e529d8_local_push_only`), which evaluates push rules for local users
only.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit141 && ./build/tests
```
