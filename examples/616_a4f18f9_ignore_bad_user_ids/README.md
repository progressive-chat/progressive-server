# Step 616 — "fix: ignore bad user ids" (Conduit `a4f18f9`)

Source: [`timokoesters/conduit@a4f18f9`](https://github.com/timokoesters/conduit/commit/a4f18f9) (2023-02)

## What changed vs step 615

| Rust change | C++ translation |
|---|---|
| Fix: ignore bad user ids. Handle malformed user IDs gracefully. | **Translated** — Our user ID validation (step 10) rejects bad IDs. This adds graceful handling. |

## Implementation details

- Our user ID validation (step 10) rejects bad IDs. This adds graceful handling.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
