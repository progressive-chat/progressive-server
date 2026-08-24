# Step 6 — "feat: save pdus" (Conduit `fa322689`, 2020-04-03)

Source: [`timokoesters/conduit@fa322689`](https://github.com/timokoesters/conduit/commit/fa322689)
— the room event DAG:

> PDUs are saved in a pduid -> pdus map. roomid -> pduleaves keeps track of
> the leaves of the event graph and eventid -> pduid maps event ids to pdus.

## Deltas vs step 5

| Rust | C++ |
|---|---|
| new `database.rs`: `Database` struct (trees as fields), `MultiValue` ('d'+id+0xff prefix, 'n'+id big-endian counter) | `src/database.{hpp,cpp}` over the RocksDB-backed sled shim |
| `pdu_get` / `pdu_leaves_replace` / `pdu_append` — depth = max(prev)+1, prev_events = old leaves, TODO placeholders for auth_events/hashes/signatures kept verbatim | identical in `data.cpp` |
| PDU id = `'d' + room_id + '#' + index` | byte-identical layout |
| real event ids via `ruma_signatures::reference_hash` | `src/crypto.{hpp,cpp}`: OpenSSL SHA-256 + redaction + base64url; nlohmann sorted dumps = canonical JSON |
| `GET /sync` skeleton (timeline was `todo!()`) | returns stored PDUs (documented improvement) |
| catch-all OPTIONS → 404 "Room not found." | preserved |
| versions trimmed back to `["r0.6.0"]` | identical |

## Verified behavior

```console
$ curl -X PUT -H "Authorization: Bearer TODO:randomtoken" -d '{"msgtype":"m.text","body":"hello"}' \
    '.../rooms/!r:localhost/send/m.room.message/t1'
{"event_id":"$jiOOSNG5WDlHniAW_8FFAy62qKEFk04iG37roCIYbRs"}
# second event: depth 2, prev_events points at the first id — the DAG is real.
# /sync returns both PDUs; everything survives restart.
```
