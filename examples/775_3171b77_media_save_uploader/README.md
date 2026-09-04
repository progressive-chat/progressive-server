# Step 775 — media_save_uploader

Source: [`timokoesters/conduit@3171b77`](https://github.com/timokoesters/conduit/commit/3171b77) (2025-05-06)

## What changed vs step 774

| Rust change | C++ translation |
|---|---|
| Stores the uploader's user_id in the `mediaid_meta` tree for each media file. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
