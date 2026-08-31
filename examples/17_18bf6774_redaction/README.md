# Step 17 — "feat: redaction" (Conduit `18bf6774`)

Source: [`timokoesters/conduit@18bf6774`](https://github.com/timokoesters/conduit/commit/18bf6774) (2020-05-31)

## What changed vs step 22

| Rust change | C++ translation |
|---|---|
| Adds `PUT /rooms/{id}/redact/{eid}/{txn_id}` route, `Data::redact_pdu` method, and `crypto::redact` helper. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
