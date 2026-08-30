# Step 34 — "fix: filter public room dir" (Conduit `9f05ef926`)

Source: [`timokoesters/conduit@9f05ef926`](https://github.com/timokoesters/conduit/commit/9f05ef926) (2020-09-14)

## What changed vs step 33

| Rust change | C++ translation |
|---|---|
| Filters `get_public_rooms_filtered_route` results by `generic_search_term` (case-insensitive on room_id and name). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
