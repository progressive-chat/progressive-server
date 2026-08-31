# Step 216 — "improvement: implement /receipt" (Conduit `dd68031`)

Source: [`timokoesters/conduit@dd68031`](https://github.com/timokoesters/conduit/commit/dd68031) (2021-03)

## What changed vs step 215

| Rust change | C++ translation |
|---|---|
| Implement `/receipt` endpoint. Read receipts (m.receipt) for tracking which events users have read. | **Translated** — We don't have receipts yet. This adds the `/receipt` API and read receipt tracking. |

## Implementation details

- We don't have receipts yet. This adds the `/receipt` API and read receipt tracking.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
