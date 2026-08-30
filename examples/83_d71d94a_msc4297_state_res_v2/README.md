# Step 83 — "feat: MSC4297, State Resolution v2.1" (Conduit `d71d94a`)

Source: [`timokoesters/conduit@d71d94a`](https://github.com/timokoesters/conduit/commit/d71d94a) (2025-08-11)

## What changed vs step 82

| Rust change | C++ translation |
|---|---|
| Adopts the v2.1 state resolution algorithm in `state_res.cpp`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
