# Step 18 — "improvement: optimize /sync response" (Conduit `b4d65ab6`, 2020-06-06)

Source: [`timokoesters/conduit@b4d65ab6`](https://github.com/timokoesters/conduit/commit/b4d65ab6)

## What changed vs step 17

| Rust change | C++ translation |
|---|---|
| joined/left/invited rooms with nothing new are **omitted** from /sync (`is_empty()` check) | responder skips rooms whose timeline+state are empty |
| first-ever sync marks `timeline.limited = true` | `limited = is_initial && last_pdu_index > 0` |
| incremental syncs return only PDUs newer than `since` | `pdus_since(room, since)` for non-initial syncs |
| `device_lists` always an object | n/a (we never emitted it optional) |

## Verified

```
initial sync            → limited:true, 5 events
incremental since=5     → rooms:{}   (nothing new — skipped)
```

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```

Note: since step 17, registration is a two-step UIAA flow — POST without
auth returns 401+session; resubmit with auth.type=m.login.dummy.
