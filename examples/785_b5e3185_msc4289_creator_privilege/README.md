# Step 785 — msc4289_creator_privilege

Source: [`timokoesters/conduit@b5e3185`](https://github.com/timokoesters/conduit/commit/b5e3185) (2025-08-10)

## What changed vs step 784

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
