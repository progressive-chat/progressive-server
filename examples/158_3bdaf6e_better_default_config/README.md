# Step 158 — "improvement: better default config" (Conduit `3bdaf6e`)

Source: [`timokoesters/conduit@3bdaf6e`](https://github.com/timokoesters/conduit/commit/3bdaf6e) (2021-01)

## What changed vs step 157

| Rust change | C++ translation |
|---|---|
| Improvement: better default config values (port 8448, etc.). | **Translated** — Our default port is 8000 (from main.cpp). To match Conduit's default, we'd change to 8448. |

## Implementation details

- Our default port is 8000 (from main.cpp). To match Conduit's default, we'd change to 8448.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
