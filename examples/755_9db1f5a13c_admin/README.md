# Step 755 — admin

Source: [`timokoesters/conduit@9db1f5a13c`](https://github.com/timokoesters/conduit/commit/9db1f5a13c) (2024-05-02)

## What changed vs step 754

| Rust change | C++ translation |
|---|---|
| Admin `register` endpoint rejects remote server names; admin subsystem routes registered. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
