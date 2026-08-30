# Step 99 — "refactor: move configuration to it's own crate" (Conduit `422bd24`)

Source: [`timokoesters/conduit@422bd24`](https://github.com/timokoesters/conduit/commit/422bd24) (2026-07-17)

## What changed vs step 98

| Rust change | C++ translation |
|---|---|
| Moves configuration to a separate crate. No-op (we use env-var-only configuration). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
