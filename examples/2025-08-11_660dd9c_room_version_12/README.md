# 2024/2025-tail — "feat: room version 12" (Conduit `660dd9c`)

Source: [`timokoesters/conduit@660dd9c`](https://github.com/timokoesters/conduit/commit/660dd9c) (2025-08-11)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Adds support for Matrix room version 12 (MSC4289 + MSC4291 + MSC4297). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
