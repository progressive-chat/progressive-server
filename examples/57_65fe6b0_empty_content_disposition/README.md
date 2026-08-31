# Step 57 — "fix: Empty content dispositions could create problems" (Conduit `65fe6b0`)

Source: [`timokoesters/conduit@65fe6b0`](https://github.com/timokoesters/conduit/commit/65fe6b0) (2024-09-25)

## What changed vs step 64

| Rust change | C++ translation |
|---|---|
| Skips the `Content-Disposition` header when the file has no filename to avoid sending `filename=""`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
