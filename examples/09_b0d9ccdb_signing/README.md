# Step 9 — "Signing, basis for federation" (Conduit `b0d9ccdb`)

Source: [`timokoesters/conduit@b0d9ccdb`](https://github.com/timokoesters/conduit/commit/b0d9ccdb) (2020-04-29)

## What changed vs step 8

| Rust change | C++ translation |
|---|---|
| Adds Ed25519 keypair persisted in DB root. `hash_and_sign_event` (sha256+ed25519) replaces fake AAAA hashes. `server_server::send_request` signs and POSTs to peers. `publicRooms` merges chunks from matrix.org. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
