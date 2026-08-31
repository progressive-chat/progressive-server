# 2024/2025-tail — "fix: set previous creators to max power level if "upgraded" room doesn't support creator power level" (Conduit `e757a98`)

Source: [`timokoesters/conduit@e757a98`](https://github.com/timokoesters/conduit/commit/e757a98) (2025-09-12)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| When upgrading a room, copies the previous room's creators to the new room's power level (max). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
