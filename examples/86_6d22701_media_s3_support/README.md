# Step 86 — "feat(service/media): add S3 support" (Conduit `6d22701`)

Source: [`timokoesters/conduit@6d22701`](https://github.com/timokoesters/conduit/commit/6d22701) (2025-08-28)

## What changed vs step 91

| Rust change | C++ translation |
|---|---|
| Adds an S3 backend option for media storage. Not implemented (we use local filesystem only). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
