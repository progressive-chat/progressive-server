# 2024/2025-tail — "feat: MSC4289, Explicitly privilege room creators (1/2)" (Conduit `b5e3185`)

Source: [`timokoesters/conduit@b5e3185`](https://github.com/timokoesters/conduit/commit/b5e3185) (2025-08-10)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Adds `RoomVersionRules.explicitly_privilege_room_creators`; `createRoom` accepts `additional_creators` field. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
