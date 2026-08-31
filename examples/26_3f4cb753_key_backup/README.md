# Step 26 — "improvement: add remaining key backup endpoints" (Conduit `3f4cb753`)

Source: [`timokoesters/conduit@3f4cb753`](https://github.com/timokoesters/conduit/commit/3f4cb753) (2020-08-27)

## What changed vs step 26

| Rust change | C++ translation |
|---|---|
| Adds 10+ REST endpoints for `/room_keys/...` plus the full `Data::backup_*` helper set. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
