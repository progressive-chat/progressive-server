# Step 25 — "Add room upgrade." (Conduit `df55e8ed`)

Source: [`timokoesters/conduit@df55e8ed`](https://github.com/timokoesters/conduit/commit/df55e8ed) (2020-08-31)

## What changed vs step 24

| Rust change | C++ translation |
|---|---|
| Adds `POST /rooms/{id}/upgrade` with tombstone event, predecessor in m.room.create, state transfer (9 event types), and alias move. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
