# Step 808 — "Remove auth_cache using a closure to fetch events in state-res" (Conduit `98f1480e`)

Source: [`timokoesters/conduit@98f1480e`](https://github.com/timokoesters/conduit/commit/98f1480e) (2021-06-29)

Upstream removes the threaded-through `auth_cache: EventMap` from
`handle_incoming_pdu` / `fetch_and_handle_events` (and its callers in
`send_transaction_message_route`, `invite_helper`,
`create_join_event_route`). Event lookups go straight to
`db.rooms.get_pdu(id)` again — cheap now that step 807 caches PDUs — and
state resolution receives a fetch closure instead of the map. Sled database
compression is also switched on.

## What changed vs step 807

| Rust change | C++ translation |
|---|---|
| **Drop the `auth_cache` parameter from `fetch_and_handle_events`** | **Implemented** — signature shrinks to `(db, origin, event_ids)`; lookups use `db.pdu_get(id)` directly with a call-local visited set against cycles/duplicates (`src/server_server.cpp`) |
| **State resolution via fetch closure instead of the cache map** | **Covered** — this port's state resolution already fetches through `Data::pdu_get()`; no separate event-map plumbing remained |
| **Sled `use_compression(true)`** | **Already compliant** — the RocksDB backing sets `kZSTD` compression on every column family (`src/sled.cpp`) |
| **Cargo/rust-toolchain bumps** | **Skipped** — dependency-only, per project rules |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit808
```
