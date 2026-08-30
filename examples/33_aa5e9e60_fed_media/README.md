# Step 33 — "feat: download media and thumbnails over federation" (Conduit `aa5e9e60`)

Source: [`timokoesters/conduit@aa5e9e60`](https://github.com/timokoesters/conduit/commit/aa5e9e60) (2020-09-14)

## What changed vs step 32

| Rust change | C++ translation |
|---|---|
| Adds `/_matrix/federation/v1/media/download` and `/_matrix/federation/v1/media/thumbnail` endpoints reusing the local download handler. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
