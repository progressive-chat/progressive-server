# Step 184 — "Append state event that pass resolution to DB, update to tokio 1.1" (Conduit `cd0c5c0`)

Source: [`timokoesters/conduit@cd0c5c0`](https://github.com/timokoesters/conduit/commit/cd0c5c0) (2021-01)

## What changed vs step 183

| Rust change | C++ translation |
|---|---|
| Append state event that pass resolution to DB, update to tokio 1.1. 6 files changed. | **Translated** — Our state-res writes resolved state to DB. The tokio 1.1 is a Rust dependency update. |

## Implementation details

- Our state-res writes resolved state to DB. The tokio 1.1 is a Rust dependency update.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
