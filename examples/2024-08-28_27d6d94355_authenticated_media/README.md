# 2024/2025-tail — "feat: add support for authenticated media requests" (Conduit `27d6d94355`)

Source: [`timokoesters/conduit@27d6d94355`](https://github.com/timokoesters/conduit/commit/27d6d94355) (2024-08-28)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Adds `_matrix/client/v1/media/config` and `v1/media/download/{server}/{id}` (auth-gated). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
