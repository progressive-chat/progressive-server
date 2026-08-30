# Step 6 — "feat: save pdus" (Conduit `fa322689`)

Source: [`timokoesters/conduit@fa322689`](https://github.com/timokoesters/conduit/commit/fa322689) (2020-04-03)

## What changed vs step 5

| Rust change | C++ translation |
|---|---|
| Adds the full PDU persistence layer. New trees: `pduid_pdus`, `roomid_pduleaves`, `eventid_pduid`. Real event IDs via `reference_hash` (sha256 of canonical event). Adds `/sync` (returns stored PDUs) and OPTIONS catch-all. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
