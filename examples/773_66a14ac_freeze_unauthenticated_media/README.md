# Step 773 — freeze_unauthenticated_media

Source: [`timokoesters/conduit@66a14ac`](https://github.com/timokoesters/conduit/commit/66a14ac) (2025-05-06)

## What changed vs step 772

| Rust change | C++ translation |
|---|---|
| Pre-fetches and freezes unauthenticated media so it can't be modified by the uploader after-the-fact. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
