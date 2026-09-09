# Step 112 — "feat: make_join, send_join and /directory" (Conduit `eedac4fd`)

Source: [`timokoesters/conduit@eedac4fd`](https://github.com/timokoesters/conduit/commit/eedac4fd) (2021-04-16)

This commit was originally merged after the TLS trio but is dated 2021-04-16,
placing it chronologically before `d4e0ba24` (2021-04-19).

## What changed vs step 111

| Rust change | C++ translation |
|---|---|
| **`GET /_matrix/federation/v1/make_join/<roomId>/<userId>`** | **Implemented** — `make_join()` returns an unsigned join event template with current room state |
| **`PUT /_matrix/federation/v2/send_join/<roomId>/<eventId>`** | **Implemented** — `send_join()` validates and persists a signed join event, returns full room state |
| **`POST /_matrix/federation/v1/publicRooms`** | **Implemented** — `get_public_rooms_federation()` serves the public room directory over federation with filter/pagination |
| **`handle_incoming_pdu` returns PDU IDs** | **Documented** — C++ already uses string event IDs; no change needed |
| **`fetch_and_handle_events` recursive fetch** | **Documented** — Already implemented in send_join flow; full recursive auth-chain fetch left for future work |

## Implementation details

1. **server_server.hpp/.cpp** — New `make_join()`, `send_join()`, `get_public_rooms_federation()` endpoints
2. **main.cpp** — Added federation routes:
   - `GET /_matrix/federation/v1/make_join/:roomId/:userId`
   - `PUT /_matrix/federation/v2/send_join/:roomId/:eventId`
   - `POST /_matrix/federation/v1/publicRooms`

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
