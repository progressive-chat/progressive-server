# Step 806 — "improvement: /search works for multiple rooms" (Conduit `dcac1361`)

Source: [`timokoesters/conduit@dcac1361`](https://github.com/timokoesters/conduit/commit/dcac1361) (2021-06-21)

Upstream generalizes `POST /_matrix/client/r0/search` from a single room
(first entry of `filter.rooms`, required) to any number of rooms: when the
filter omits `rooms`, every room the user joined is searched, per-room
matches merge, and highlights come from the search term itself.

## What changed vs step 805

| Rust change | C++ translation |
|---|---|
| **`filter.rooms` optional, defaulting to all joined rooms** | **Implemented** — `Data::search_pdus(room_id, term)` (case-insensitive over type/sender/content body) runs per room; rooms default to `rooms_joined(sender)` |
| **Reject rooms the user hasn't joined (`M_FORBIDDEN`)** | **Implemented** — every target room is checked with `is_joined` before searching |
| **Merged newest-first results with `skip + limit` pagination** | **Implemented** — per-room match lists merge by largest event id; `filter.limit` clamped to [0, 100], `next_batch` is the skip offset token |
| **Highlights from the search term** | **Implemented** — term split on non-alphanumerics, lowercased (upstream `split_terminator`) |
| **Spec-shaped `search_categories.room_events` response** | **Implemented** — `{count, highlights, next_batch?, results: [{rank, result}]}` with full event objects via `pdu_get` |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit806
# create rooms, send messages, then:
$ curl -s -H "Authorization: Bearer $TOKEN" -d '{"search_categories":{"room_events":{"search_term":"hello"}}}' http://127.0.0.1:8000/_matrix/client/r0/search
```
