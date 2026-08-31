# Step 84 — "refactor(service/media): make all fs operations async" (Conduit `5f3bda8`)

Source: [`timokoesters/conduit@5f3bda8`](https://github.com/timokoesters/conduit/commit/5f3bda8) (2025-08-28)

## What changed vs step 83

| Rust change | C++ translation |
|---|---|
| Media file operations are wrapped in `std::async` for offloading. No-op (we use synchronous file I/O). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
