# 2024/2025-tail — "fix: use append_member_pdu for `/invite`" (Conduit `3db42bd`)

Source: [`timokoesters/conduit@3db42bd`](https://github.com/timokoesters/conduit/commit/3db42bd) (2025-12-22)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Adds `federation::handle_member_pdu` helper for room-version-aware join/invite/knock handling. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
