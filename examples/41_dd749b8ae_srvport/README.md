# Step 41 — "fix: server keys and destination resolution when server name contains port" (Conduit `dd749b8ae`)

Source: [`timokoesters/conduit@dd749b8ae`](https://github.com/timokoesters/conduit/commit/dd749b8ae) (2020-09-16)

## What changed vs step 40

| Rust change | C++ translation |
|---|---|
| `send_request` parses destination for `:port`; if present uses it, else falls back to 8448. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
