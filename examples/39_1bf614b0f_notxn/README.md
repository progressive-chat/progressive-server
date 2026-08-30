# Step 39 — "fix: remove transaction_id from pdus over federation" (Conduit `1bf614b0f`)

Source: [`timokoesters/conduit@1bf614b0f`](https://github.com/timokoesters/conduit/commit/1bf614b0f) (2020-09-15)

## What changed vs step 38

| Rust change | C++ translation |
|---|---|
| `federation_send_to_remotes` erases `unsigned.transaction_id` before sending. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
