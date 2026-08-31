# Step 85 — "fix: remove transaction_id from pdus over federation" (Conduit `1bf614b`)

Source: [`timokoesters/conduit@1bf614b`](https://github.com/timokoesters/conduit/commit/1bf614b) (2020-09)

## What changed vs step 84

| Rust change | C++ translation |
|---|---|
| Removes `unsigned.transaction_id` from PDUs before sending them over federation (the txn_id is a client concept, not a server one). | Our step 39 (`1bf614b0f_notxn`) implements this in `federation_send_to_remotes`. |

## Implementation details

- Our step 39 (`1bf614b0f_notxn`) implements this in `federation_send_to_remotes`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
