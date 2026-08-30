# Step 31 — "improvement: try out multiple servers when joining remote rooms" (Conduit `c5313b3e`)

Source: [`timokoesters/conduit@c5313b3e`](https://github.com/timokoesters/conduit/commit/c5313b3e) (2020-09-14)

## What changed vs step 30

| Rust change | C++ translation |
|---|---|
| Alias joins resolve via federation `query/directory`, parse the `servers` field, and try each candidate server with `make_join` + `send_join`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
