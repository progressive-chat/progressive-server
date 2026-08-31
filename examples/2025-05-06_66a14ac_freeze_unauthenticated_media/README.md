# 2024/2025-tail — "feat: freeze unauthenticated media" (Conduit `66a14ac`)

Source: [`timokoesters/conduit@66a14ac`](https://github.com/timokoesters/conduit/commit/66a14ac) (2025-05-06)

## What changed vs step 44 (last 2020 step)

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
