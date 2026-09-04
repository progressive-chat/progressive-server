# Step 764 — media_content_disposition

Source: [`timokoesters/conduit@423b092`](https://github.com/timokoesters/conduit/commit/423b092) (2024-08-22)

## What changed vs step 763

| Rust change | C++ translation |
|---|---|
| Uses the sanitized content-type in the `Content-Disposition` header rather than just octet-stream. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
