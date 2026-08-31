# Step 81 — "feat: send messages over federation" (Conduit `f7816b1`)

Source: [`timokoesters/conduit@f7816b1`](https://github.com/timokoesters/conduit/commit/f7816b1) (2020-09)

## What changed vs step 80

| Rust change | C++ translation |
|---|---|
| Adds the federation send message flow. When a user sends a message in a room with remote servers, we forward the PDU to each remote server via `/send`. | Our step 35 (`f7816b11d_fed_sendmsg`) implements the federation PDU send with `federation_send_to_remotes`. |

## Implementation details

- Our step 35 (`f7816b11d_fed_sendmsg`) implements the federation PDU send with `federation_send_to_remotes`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
