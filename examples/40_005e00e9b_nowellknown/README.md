# Step 40 — "fix: remove well-known" (Conduit `005e00e9b`)

Source: [`timokoesters/conduit@005e00e9b`](https://github.com/timokoesters/conduit/commit/005e00e9b) (2020-09-15)

## What changed vs step 39

| Rust change | C++ translation |
|---|---|
| `send_request` no longer calls `request_well_known`; the helper remains defined but unused. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
