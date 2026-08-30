# Step 101 — "feat: rate-limiting" (Conduit `11a9d05`)

Source: [`timokoesters/conduit@11a9d05`](https://github.com/timokoesters/conduit/commit/11a9d05) (2026-07-17)

## What changed vs step 100

| Rust change | C++ translation |
|---|---|
| Adds `rate_limiting.{hpp,cpp}` with `PrivateSmall` preset and sliding window per (action, IP+token). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
