# Step 61 — "refactor: set send_request matrix versions in a single constant" (Conduit `4dc15a4`)

Source: [`timokoesters/conduit@4dc15a4`](https://github.com/timokoesters/conduit/commit/4dc15a4) (2025-03-08)

## What changed vs step 67

| Rust change | C++ translation |
|---|---|
| Centralizes the supported Matrix versions into a single `MATRIX_VERSIONS = "V1_13"` constant used in User-Agent. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
