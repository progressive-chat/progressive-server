# Step 770 — keys_upload_validation

Source: [`timokoesters/conduit@42d8e88`](https://github.com/timokoesters/conduit/commit/42d8e88) (2025-03-03)

## What changed vs step 769

| Rust change | C++ translation |
|---|---|
| Validates `one_time_keys` and `device_keys` deserialization in `POST /keys/upload`; rejects malformed entries with M_BAD_JSON. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
