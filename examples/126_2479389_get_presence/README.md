# Step 126 — "feat: implement GET /presence" (Conduit `2479389`)

Source: [`timokoesters/conduit@2479389`](https://github.com/timokoesters/conduit/commit/2479389) (2021-05-14)

Upstream adds `GET /_matrix/client/r0/presence/{userId}/status`, which reads
the latest stored `m.presence` event for the requested user across rooms the
two users share.

## What changed vs step 125

**This directory used to be a byte-identical copy** of the attempt-A series'
base (the same April-2021 `src/` as `122_8bfaf09_cleanup_response_conv` through
`149_67f9592_event_auth`). That base predates the feature and has no presence
storage at all, so the step is rebuilt on the modern codebase (step 813) and
now really implements the commit:

| Rust change | C++ translation |
|---|---|
| **`get_presence_route` (`GET /presence/<_>/status`)** | **Implemented** — finds shared rooms, reads the latest presence event, returns `{presence, status_msg, currently_active, last_active_ago}` |
| **`get_last_presence_event(user, room)` in `edus.rs`** | **Implemented** — `Data::get_last_presence_event()` over the new `userroomid_presence` tree; stored timestamps are converted to a `last_active_ago` duration |
| **`set_presence_route` + `update_presence` (prerequisite from earlier commits)** | **Folded** — this port had no presence at all, so `PUT /presence/{userId}/status` and `Data::update_presence()` are included |
| **`get_shared_rooms` (prerequisite)** | **Folded** — `Data::shared_rooms()` intersects both users' joined rooms |
| **`userid_lastpresenceupdate` timestamp tree + count-stamped `presenceid_presence`** | **Simplified** — one `userroomid_presence` row per (user, room) holding the latest event, which is all the GET reads |

Documented deviations from upstream (both in `main.cpp`):
- Upstream `get_presence_route` calls `get_last_presence_event(&sender_user, …)`
  — a bug that returns the *requester's* presence. This port reads the
  requested user's presence as intended.
- Upstream `todo!()`s (panics) when no presence event is found; this port
  returns `{"presence":"offline"}` with 200.

Steps covered elsewhere on the way here: `123` (cf94b8e, UIAA like synapse)
is implemented in the modern chain as step 118; `124` (3408d74) is a
docs/config-only commit; `125` (af6fea3) is a canonical-JSON refactor. The
older copies `38`–`122` in the attempt-A/B series either duplicate commits
already implemented in the modern chain or are no-ops whose fixes were folded
early (e.g. `38`'s origin field has been set in `pdu_append` since step 30).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit126
# alice sets presence; bob (sharing a room) reads it back:
$ curl -s -X PUT -H "Authorization: Bearer $ALICE" -d '{"presence":"online","status_msg":"hi"}' \
    http://127.0.0.1:8000/_matrix/client/r0/presence/@alice:localhost/status
$ curl -s -H "Authorization: Bearer $BOB" \
    http://127.0.0.1:8000/_matrix/client/r0/presence/@alice:localhost/status
{"last_active_ago":4,"presence":"online","status_msg":"hi"}
```
