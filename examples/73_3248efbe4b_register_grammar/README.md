# Step 73 — "fix(registration): enforce the strict user ID grammar" (Conduit `3248efbe4b`)

Source: [`timokoesters/conduit@3248efbe4b`](https://github.com/timokoesters/conduit/commit/3248efbe4b) (2025-06-22)

## What changed vs step 51

| Rust change | C++ translation |
|---|---|
| `register_route` rejects localparts that don't match the strict grammar; returns M_INVALID_USERNAME. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
