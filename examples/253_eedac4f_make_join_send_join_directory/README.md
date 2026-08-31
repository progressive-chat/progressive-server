# Step 253 — "feat: make_join, send_join and /directory" (Conduit `eedac4f`)

Source: [`timokoesters/conduit@eedac4f`](https://github.com/timokoesters/conduit/commit/eedac4f) (2021-04)

## What changed vs step 252

| Rust change | C++ translation |
|---|---|
| Feat: `make_join`, `send_join` and `/directory`. Implement the full join flow with directory lookup. 4 files changed. | **Translated** — Our join flow (step 25, 93) has `make_join`/`send_join`. `/directory` is new. |

## Implementation details

- Our join flow (step 25, 93) has `make_join`/`send_join`. `/directory` is new.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
