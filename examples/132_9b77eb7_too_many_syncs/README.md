# Step 132 — "fix: too many syncs" (Conduit `9b77eb7`)

Source: [`timokoesters/conduit@9b77eb7`](https://github.com/timokoesters/conduit/commit/9b77eb7) (2021-05-22)

Upstream re-adds the `pdus_after_since` gate (removed the day before in
`3e2f742`) so room state/counts are only recomputed when events actually
arrived after `since`.

## What changed vs step 131

**Nothing in `src/` — this directory was a byte-identical copy.** The port's
simplified sync has no state-hash gate at all — it always recomputes every
joined room from scratch — so there is no gate to add or remove.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit132 && ./build/tests
```
