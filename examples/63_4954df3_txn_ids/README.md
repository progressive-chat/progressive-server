# Step 63 — "feat: handle txn ids" (Conduit `4954df3`)

Source: [`timokoesters/conduit@4954df3`](https://github.com/timokoesters/conduit/commit/4954df3) (2020-08)

## What changed vs step 62

| Rust change | C++ translation |
|---|---|
| Adds transaction ID deduplication. When a client sends a PUT request with a `transaction_id`, the server remembers the response and returns it again for duplicate requests within 5 seconds. | **Translated** — our step 26 (`4954df3c_txn_ids`) implements this with the `userdevicetxnid_response` sled tree. |

## Implementation details

- **Translated** — our step 26 (`4954df3c_txn_ids`) implements this with the `userdevicetxnid_response` sled tree.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
