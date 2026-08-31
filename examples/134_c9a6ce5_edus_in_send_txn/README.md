# Step 134 — "Add basic handling of EDUs for /send/txn" (Conduit `c9a6ce5`)

Source: [`timokoesters/conduit@c9a6ce5`](https://github.com/timokoesters/conduit/commit/c9a6ce5) (2020-12)

## What changed vs step 133

| Rust change | C++ translation |
|---|---|
| Adds basic handling of EDUs (typing, receipts, presence) in `/send/{txnId}`. Previously only PDUs were sent. | **No-op for us** — We don't have EDU handling yet (gap from `3debb620`, `3b9cadee`, `ee0d6940` 2020 commits). |

## Implementation details

- We don't have EDU handling yet (gap from `3debb620`, `3b9cadee`, `ee0d6940` 2020 commits).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
