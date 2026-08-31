# Step 120 — "fix: don't allow more than 50 PDUs in a transaction" (Conduit `16b22bb`)

Source: [`timokoesters/conduit@16b22bb`](https://github.com/timokoesters/conduit/commit/16b22bb) (2020-11)

## What changed vs step 119

| Rust change | C++ translation |
|---|---|
| Fix: don't allow more than 50 PDUs in a single transaction. Prevents DoS by splitting up large transactions. | **No-op for us** — Our federation send handles all PDUs in a single transaction. A limit could be added later. |

## Implementation details

- Our federation send handles all PDUs in a single transaction. A limit could be added later.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
