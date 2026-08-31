# Step 58 — "fix(media): return an error when content is failed to be parsed as an image" (Conduit `30855ce`)

Source: [`timokoesters/conduit@30855ce`](https://github.com/timokoesters/conduit/commit/30855ce) (2025-02-04)

## What changed vs step 57

| Rust change | C++ translation |
|---|---|
| Returns a proper error when image thumbnail generation fails (instead of crashing). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
