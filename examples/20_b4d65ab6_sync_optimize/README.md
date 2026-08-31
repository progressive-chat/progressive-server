# Step 20 — "improvement: optimize /sync response" (Conduit `b4d65ab6`)

Source: [`timokoesters/conduit@b4d65ab6`](https://github.com/timokoesters/conduit/commit/b4d65ab6) (2020-06-08)

## What changed vs step 19

| Rust change | C++ translation |
|---|---|
| Joins/leaves/invites with nothing new are omitted from /sync. First-ever sync marks `timeline.limited = true`. Incremental syncs return only PDUs newer than `since` via `pdus_since(room, since)`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
