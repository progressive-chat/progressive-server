# Step 42 — "fix: synapse complains about missing origin" (Conduit `f4078a29e`)

Source: [`timokoesters/conduit@f4078a29e`](https://github.com/timokoesters/conduit/commit/f4078a29e) (2020-09-16)

## What changed vs step 41

| Rust change | C++ translation |
|---|---|
| Stamps `pdu["origin"] = kServerName` in `federation_send_to_remotes`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
