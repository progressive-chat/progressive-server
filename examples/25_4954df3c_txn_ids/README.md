# Step 25 — "feat: handle txn ids" (Conduit `4954df3c`)

Source: [`timokoesters/conduit@4954df3c`](https://github.com/timokoesters/conduit/commit/4954df3c) (2020-08-25)

## What changed vs step 25

| Rust change | C++ translation |
|---|---|
| Adds `userdevicetxnid_response` sled tree and `add_txnid`/`existing_txnid` helpers for PUT/GET dedup. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
