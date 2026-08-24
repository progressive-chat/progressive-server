# Step 6 — "feat: save pdus" (Conduit `fa322689`, 2020-04-03)

Source: [`timokoesters/conduit@fa322689`](https://github.com/timokoesters/conduit/commit/fa322689)
— the commit where Conduit stops being a user registry and starts storing the
**room event DAG**. Commit message upstream:

> PDUs are saved in a pduid -> pdus map. roomid -> pduleaves keeps track of
> the leaves of the event graph and eventid -> pduid maps event ids to pdus.

(Folded in: the small intermediate refactors that created `database.rs` and
`MultiValue` — `dba6c466`, `8b8381bc` era.)

## What changed vs step 5

| Rust change | C++ translation |
|---|---|
| new `database.rs`: `Database` struct with trees as fields; `MultiValue` = one id → many values via `'d'+id+0xff` prefix + `'n'+id` big-endian counter | `stubdb::Database`, `stubdb::MultiValue`; `Tree::scan_prefix/get_gt/update_and_fetch` (`database.hpp/cpp`) |
| `Data { hostname: String, db: Database }` — hostname cached in memory | same fields; **C++ ownership note**: Database's trees point into the owned `Db`, declared first |
| `pdu_leaves_replace(room_id, event_id)` — old leaves out, new leaf in | identical |
| `pdu_append`: `prev_events` = old leaves; `depth` = max(prev)+1; inserts `origin`, `auth_events:["$auth_eventid"]`, 64×`"A"` hashes, `"signature"` — all TODO placeholders upstream, kept verbatim | `Data::pdu_append` (`data.cpp`) |
| PDU id layout: `'d' + room_id + '#' + index` | identical byte layout |
| **real event ids**: `$` + base64url(sha256(canonical_json(redact(event)))) via `ruma_signatures::reference_hash` | hand-written SHA-256 + base64url + redaction + canonicalizer in `crypto.hpp/cpp` + `json_value.hpp/cpp` (~350 lines replacing ruma-signatures/serde) |
| `GET /_matrix/client/r0/sync` skeleton — `timeline.events` was **`todo!()`** | filled in: returns stored PDUs (documented improvement) |
| catch-all `OPTIONS /<_segments..>` returning 404 "Room not found." | identical weirdness preserved |
| versions list trimmed back to `["r0.6.0"]` | identical |

## Behavior

```console
$ curl -X PUT -H "Authorization: Bearer TODO:randomtoken" -d '{"msgtype":"m.text","body":"hello"}' \
    '.../rooms/!r:localhost/send/m.room.message/t1'
{"event_id":"$jiOOSNG5WDlHniAW_8FFAy62qKEFk04iG37roCIYbRs"}     # real hash!

# second message references the first as prev_event, depth increments:
{..."depth":2,"event_id":"$g4ZLBJkF8kzngbeqJAFf4dAZ_YnRLG_nZH33EkMHlkA",
 "prev_events":["$jiOOSNG5WDlHniAW_8FFAy62qKEFk04iG37roCIYbRs"]...}

$ curl -H "Authorization: Bearer TODO:randomtoken" '.../_matrix/client/r0/sync'
→ full timeline of both PDUs (canonical JSON, sorted keys)
```

Storage files after this step: `pduid_pdus.kv` (`d!room#1` → pdu json, `n!room`
→ counter), `roomid_pduleaves.kv`, `eventid_pduid.kv`.

## Build & run

```console
$ g++ -std=c++23 -Wall -Wextra *.cpp -o conduit_step06 && ./conduit_step06
```

## C++ study notes

1. The dangling-reference trap this step hit for real: `Database` views into a
   `Db` that died on return → `bad_alloc`. Rust's ownership makes that
   impossible; C++ makes you encode it in declaration order + comments.
2. SHA-256 from scratch (~90 lines): padding schedule, message schedule, the
   64-round compression. Verify against `sha256("abc")`.
3. Canonical JSON is why `std::map` (sorted) was chosen over `unordered_map`.
4. The room DAG is now three KV indexes over one relation — next commits will
   build /sync pagination on exactly these keys.
