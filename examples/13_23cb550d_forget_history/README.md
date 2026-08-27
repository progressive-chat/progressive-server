# Step 13 — "forget rooms, load history" (Conduit `23cb550d`, 2020-04-28)

Source: [`timokoesters/conduit@23cb550d`](https://github.com/timokoesters/conduit/commit/23cb550d)

Folded prerequisite: the leave flow (`userid_leftroomids` tree,
`room_leave`, POST /rooms/<id>/leave) that `forget` depends on.

## What changed vs step 12

| Rust change | C++ translation |
|---|---|
| `Data::room_forget(room_id, user_id)` — `userid_leftroomids.remove_value` | identical via `MultiValue::remove_value` |
| `room_pdu_first(room_id, pdu_index)` — `get_lt` finds nothing smaller | same, using decimal-string cursor matching stored keys |
| `pdus_until(room_id, until)` — walk `get_lt` backwards within room prefix | identical walk |
| POST /rooms/<id>/forget | route added |
| GET /rooms/<id>/messages?from&dir — back-pagination; dir=f is `todo!()` upstream | implemented for dir=b; dir=f returns empty chunk (documented deviation) |
| /sync: `timeline.prev_batch = since.to_string()`; joined `limited: None` | prev_batch = last_pdu_index per room |

## Verified

```console
$ # after createRoom + 3 messages:
$ curl ".../rooms/$RID/messages?from=7&dir=b"   # prev_batch=7 from /sync
count 6, newest-first: msg2, member-join, name, power_levels, create
$ curl -X POST .../rooms/$RID/leave    -> {} [200]
$ curl -X POST .../rooms/$RID/forget   -> {} [200]
$ sync join keys -> []                  # forgotten
```

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```

## Study note

The `get_lt` cursor must match the STORED key layout byte-for-byte. Our pdu
ids are `'d'+room+'#'+decimal`; a big-endian byte cursor (upstream's layout)
never matches and silently returns nothing — the kind of bug that only shows
up as "empty results", never as an error.
