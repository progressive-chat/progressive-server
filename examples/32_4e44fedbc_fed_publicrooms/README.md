# Step 32 — "fix: room list over federation" (Conduit `4e44fedbc`)

Source: [`timokoesters/conduit@4e44fedbc`](https://github.com/timokoesters/conduit/commit/4e44fedbc) (2020-09-14)

## What changed vs step 31

| Rust change | C++ translation |
|---|---|
| Adds `GET /_matrix/federation/v1/publicRooms` returning the same body as the local `get_public_rooms_filtered_route`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
