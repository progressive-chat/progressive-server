# Step 30 — "improvement: better federation joins" (Conduit `1f292c09`)

Source: [`timokoesters/conduit@1f292c09`](https://github.com/timokoesters/conduit/commit/1f292c09) (2020-09-14)

## What changed vs step 29

| Rust change | C++ translation |
|---|---|
| Adds `POST /_matrix/federation/v1/send/{txn_id}` accepting `{pdus: [...]}`, appending each to existing rooms. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
