# Step 185 — "Fix and integrate outlier tree, build forks after adding event to DB" (Conduit `56b816a`)

Source: [`timokoesters/conduit@56b816a`](https://github.com/timokoesters/conduit/commit/56b816a) (2021-01)

## What changed vs step 184

| Rust change | C++ translation |
|---|---|
| Fix and integrate outlier tree, build forks after adding event to DB. 3 files changed. | **Translated** — Our outlier handling is in state-res (step 83). The fork building is part of the state resolution. |

## Implementation details

- Our outlier handling is in state-res (step 83). The fork building is part of the state resolution.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
