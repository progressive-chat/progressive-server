# 2024/2025-tail — "fix: don't lookup create event when converting stripped state" (Conduit `03dfa72`)

Source: [`timokoesters/conduit@03dfa72`](https://github.com/timokoesters/conduit/commit/03dfa72) (2025-08-16)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Skips the create event lookup when converting stripped state to m.room.member events. No-op for us (no create event lookup in stripped path). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
