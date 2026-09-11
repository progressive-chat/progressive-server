# Step 151 — "fix: send state in /sync, element displays wrong membership changes" (Conduit `f12fbca`)

Source: [`timokoesters/conduit@f12fbca`](https://github.com/timokoesters/conduit/commit/f12fbca) (2020-12-22)

Upstream sends room state in `/sync` (previously always empty): full current
state on initial sync, and the state events changed since `since` (minus
ones already in the timeline) on incremental syncs, so clients can render
membership changes. This directory used to be a byte-identical copy of the
attempt-A base; it is rebuilt on the previous real step (128) and now really
implements the fix.

## What changed vs step 128

| Rust change | C++ translation |
|---|---|
| **Sync `state.events`: full state on initial sync, changed state otherwise** | **Implemented** — initial syncs carry the full current state; incremental syncs carry state events not already in the timeline chunk (upstream diffs against since-state, which this simplified sync does not track) |
| **State events included in the room payload** | **Implemented** — new `SyncResponse::state_events`, emitted as `state.events`; rooms with only state changes are no longer skipped as empty |
| **`unsigned.prev_content` for state events in `append_pdu`** | **Already covered** — the port has written `prev_content` since the `4cc0a070` translation |
| **Borrow-only changes (`&to_canonical_object` → value, `iter()` vs `into_iter`)** | **No-op** — Rust ownership refactor, no behavior change |
| **Simplified `limited` computation** | **Already covered** — the port marks first syncs limited; the upstream condition it simplifies does not exist here |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit151
# initial sync carries the room's state (create/member/power-levels/...):
$ curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8000/_matrix/client/r0/sync?since=0" \
  | jq '.rooms.join[].state.events | map(.type) | unique'
```
