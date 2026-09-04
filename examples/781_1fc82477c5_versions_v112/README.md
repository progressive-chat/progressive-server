# Step 781 — versions_v112

Source: [`timokoesters/conduit@1fc82477c5`](https://github.com/timokoesters/conduit/commit/1fc82477c5) (2025-05-12)

## What changed vs step 780

| Rust change | C++ translation |
|---|---|
| Adds `v1.12` to the `versions` response list. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
