# Step 674 — "fix: actually clear memory in the admin commands" (Conduit `edd4a37`)

Source: [`timokoesters/conduit@edd4a37`](https://github.com/timokoesters/conduit/commit/edd4a37) (2023-07)

## What changed vs step 673

| Rust change | C++ translation |
|---|---|
| Fix: actually clear memory in the admin commands. Admin memory clearing command. 1 file changed. | **No-op for us** — We don't have LRU caches or admin memory clearing commands yet. |

## Implementation details

- Conduit uses `LruCache` for various caches (PDU, short event ID, auth chain, event ID short, state key short, users, appservice, last timeline count)
- The fix properly recreates caches with their original capacity instead of just clearing
- Our implementation doesn't have these LRU caches yet, so this is a no-op

**Status:** No-op (infrastructure not yet implemented).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```