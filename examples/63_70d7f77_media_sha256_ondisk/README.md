# Step 63 — "feat(media): use file's sha256 for on-disk name & make directory configurable" (Conduit `70d7f77`)

Source: [`timokoesters/conduit@70d7f77`](https://github.com/timokoesters/conduit/commit/70d7f77) (2025-05-06)

## What changed vs step 70

| Rust change | C++ translation |
|---|---|
| Media files are stored on disk with their SHA-256 hash as the filename; metadata in `mediaid_meta` tree. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
