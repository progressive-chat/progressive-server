# Step 711 — "log room ID for invalid room topic event errors" (Conduit `fbd8090`)

Source: [`timokoesters/conduit@fbd8090`](https://github.com/timokoesters/conduit/commit/fbd8090) (2023-08)

## What changed vs step 710

| Rust change | C++ translation |
|---|---|
| Log room ID for invalid room topic event errors. Better error context. 2 files changed. | **Translated** — Our room topic errors (step 8) include room ID. This adds it in Rust. |

## Implementation details

- Our room topic errors (step 8) include room ID. This adds it in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
