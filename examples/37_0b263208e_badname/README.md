# Step 37 — "fix: don't panic on bad server names" (Conduit `0b263208e`)

Source: [`timokoesters/conduit@0b263208e`](https://github.com/timokoesters/conduit/commit/0b263208e) (2020-09-15)

## What changed vs step 36

| Rust change | C++ translation |
|---|---|
| `send_request` rejects empty/non-`(alnum|.|-|:|_)` destinations with a warning and returns `nullopt`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
