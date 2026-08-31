# Step 206 — "Append state event that pass resolution to DB, update to tokio 1.1" (Conduit `6fd3e1d`)

Source: [`timokoesters/conduit@6fd3e1d`](https://github.com/timokoesters/conduit/commit/6fd3e1d) (2021-02)

## What changed vs step 205

| Rust change | C++ translation |
|---|---|
| Append state event that pass resolution to DB, update to tokio 1.1. Duplicate of step 184 (cd0c5c0). | **Translated** — Our state-res writes resolved state to DB. |

## Implementation details

- Our state-res writes resolved state to DB.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
