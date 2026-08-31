# Step 49 — "fix: make media response match spec" (Conduit `965b6df83d`)

Source: [`timokoesters/conduit@965b6df83d`](https://github.com/timokoesters/conduit/commit/965b6df83d) (2024-05-06)

## What changed vs step 46

| Rust change | C++ translation |
|---|---|
| `sanitize_content_type` passes through only `image/jpeg`/`image/png`, forces everything else to `application/octet-stream`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
