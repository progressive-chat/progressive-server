# Step 207 — "Fix and integrate outlier tree, build forks after adding event to DB" (Conduit `6661de5`)

Source: [`timokoesters/conduit@6661de5`](https://github.com/timokoesters/conduit/commit/6661de5) (2021-02)

## What changed vs step 206

| Rust change | C++ translation |
|---|---|
| Fix and integrate outlier tree, build forks after adding event to DB. Duplicate of step 185 (56b816a). | **Translated** — Our outlier handling is in state-res (step 83). |

## Implementation details

- Our outlier handling is in state-res (step 83).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
