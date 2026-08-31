# 2024/2025-tail — "feat: updated MSC4311 support" (Conduit `1c6b2e0`)

Source: [`timokoesters/conduit@1c6b2e0`](https://github.com/timokoesters/conduit/commit/1c6b2e0) (2025-09-12)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Updated MSC4311 support to include the create event in the `auth_chain` of all state events. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
