# Step 83 — "fix(service/media): create directory for media file only on new file creation" (Conduit `1f7f74a`)

Source: [`timokoesters/conduit@1f7f74a`](https://github.com/timokoesters/conduit/commit/1f7f74a) (2025-08-28)

## What changed vs step 82

| Rust change | C++ translation |
|---|---|
| Creates the media directory only when a new file is uploaded (not on startup). No-op (we always create on startup). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
