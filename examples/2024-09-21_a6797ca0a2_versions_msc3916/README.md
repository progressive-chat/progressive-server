# 2024/2025-tail — "fix: add missing msc3916 unstable feature in version response" (Conduit `a6797ca0a2`)

Source: [`timokoesters/conduit@a6797ca0a2`](https://github.com/timokoesters/conduit/commit/a6797ca0a2) (2024-09-21)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| `unstable_features = {{"org.matrix.msc3916.stable", "true"}}` in the `versions` response. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
