# Step 36 — "fix: send to all servers and fix media store" (Conduit `71500b14b`)

Source: [`timokoesters/conduit@71500b14b`](https://github.com/timokoesters/conduit/commit/71500b14b) (2020-09-15)

## What changed vs step 35

| Rust change | C++ translation |
|---|---|
| Federation send iterates all participating servers. Media store keys by `mxc+filename+content_type`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
