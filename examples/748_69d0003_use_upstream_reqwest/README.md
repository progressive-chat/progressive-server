# Step 748 — "Use upstream `reqwest` instead of vendored one" (Conduit `69d0003`)

Source: [`timokoesters/conduit@69d0003`](https://github.com/timokoesters/conduit/commit/69d0003) (2024-01)

## What changed vs step 747

| Rust change | C++ translation |
|---|---|
| Use upstream `reqwest` instead of vendored one. HTTP client library change. 3 files changed. | **No-op for us** — Rust reqwest — our C++ uses httplib. |

## Implementation details

- Rust reqwest — our C++ uses httplib.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
