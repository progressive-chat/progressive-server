# Step 38 — "fix: sending slowness" (Conduit `b7ab57897`)

Source: [`timokoesters/conduit@b7ab57897`](https://github.com/timokoesters/conduit/commit/b7ab57897) (2020-09-15)

## What changed vs step 37

| Rust change | C++ translation |
|---|---|
| Hands the federation send off to a detached `std::thread` (`federation_send_background`). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
