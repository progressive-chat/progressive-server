# Step 29 — "fix: join rooms over federation" (Conduit `12a8c9ba`)

Source: [`timokoesters/conduit@12a8c9ba`](https://github.com/timokoesters/conduit/commit/12a8c9ba) (2020-09-12)

## What changed vs step 28

| Rust change | C++ translation |
|---|---|
| Adds server-side federation endpoints: `/send_join/{r}/{u}`, `/state_ids/{r}/{u}`, `/event/{eid}`, `/backfill/{r}`, `/query/directory`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
