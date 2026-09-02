# Step 88 — "improvement: implement /receipt" (Conduit `dd68031`)

Source: [`timokoesters/conduit@dd68031`](https://github.com/timokoesters/conduit/commit/dd68031) (2021-03-02)

## What changed vs step 87

| Rust change | C++ translation |
|---|---|
| **Implement /receipt** | **Translated** — Receipts support |
| **Major read_marker refactor** | **Translated** — Read marker improvements |

## Implementation details

1. **Receipts support** — Implement /receipt endpoint
2. **Read marker improvements** — Better read marker handling

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
