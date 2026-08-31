# Step 430 — "fix: mention dependencies to build from source" (Conduit `bfcf2db`)

Source: [`timokoesters/conduit@bfcf2db`](https://github.com/timokoesters/conduit/commit/bfcf2db) (2022-02)

## What changed vs step 429

| Rust change | C++ translation |
|---|---|
| Fix: mention dependencies to build from source. Duplicate of step 422. | **Skipped** — Documentation only (duplicate). |

## Implementation details

- Documentation only (duplicate).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
