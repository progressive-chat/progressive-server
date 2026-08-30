# Step 12 — "feat: user renaming" (Conduit `4cc0a070`)

Source: [`timokoesters/conduit@4cc0a070`](https://github.com/timokoesters/conduit/commit/4cc0a070) (2020-04-29)

## What changed vs step 11

| Rust change | C++ translation |
|---|---|
| Adds `displayname_set`/`displayname_get`. `displayname_set` broadcasts m.room.member join events per joined room. `room_join` includes the displayname. `get_alias_route` checks the alias's server_name. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
