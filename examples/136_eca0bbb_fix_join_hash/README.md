# Step 136 — "Fix federated join miss hashing the join event created" (Conduit `eca0bbb`)

Source: [`timokoesters/conduit@eca0bbb`](https://github.com/timokoesters/conduit/commit/eca0bbb) (2020-12)

## What changed vs step 135

| Rust change | C++ translation |
|---|---|
| Fix: federated join was missing hashing the join event. Without this, the join event ID would be different from the server's expectation. | **Translated** — Our `crypto::reference_hash` computes the correct event ID for all events including joins. |

## Implementation details

- Our `crypto::reference_hash` computes the correct event ID for all events including joins.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
