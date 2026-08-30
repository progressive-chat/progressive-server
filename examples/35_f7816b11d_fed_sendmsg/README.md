# Step 35 — "feat: send messages over federation" (Conduit `f7816b11d`)

Source: [`timokoesters/conduit@f7816b11d`](https://github.com/timokoesters/conduit/commit/f7816b11d) (2020-09-15)

## What changed vs step 34

| Rust change | C++ translation |
|---|---|
| Adds `room_servers()` helper and `federation_send_to_remotes` to deliver a local PDU to each remote room server. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
