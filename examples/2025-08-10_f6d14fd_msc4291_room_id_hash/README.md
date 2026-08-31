# 2024/2025-tail — "feat: MSC4291, Room IDs as hashes of the create event (1/2)" (Conduit `f6d14fd`)

Source: [`timokoesters/conduit@f6d14fd`](https://github.com/timokoesters/conduit/commit/f6d14fd) (2025-08-10)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Adds `generate_room_id_v1` helper that hashes the canonical create event with SHA-256. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
