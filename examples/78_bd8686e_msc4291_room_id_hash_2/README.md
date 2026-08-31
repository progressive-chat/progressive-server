# Step 78 — "feat: MSC4291, Room IDs as hashes of the create event (2/2)" (Conduit `bd8686e`)

Source: [`timokoesters/conduit@bd8686e`](https://github.com/timokoesters/conduit/commit/bd8686e) (2025-08-11)

## What changed vs step 81

| Rust change | C++ translation |
|---|---|
| Updates `createRoom` to use the hash-based room ID from MSC4291 when the room version supports it. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
