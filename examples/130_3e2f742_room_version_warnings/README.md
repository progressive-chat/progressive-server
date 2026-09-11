# Step 130 — "fix: room version warnings and other bugs when joining rooms" (Conduit `3e2f742`)

Source: [`timokoesters/conduit@3e2f742`](https://github.com/timokoesters/conduit/commit/3e2f742) (2021-05-21)

Upstream reorders the join-event store (compute the state hash before
allocating the PDU id), drops a redundant membership write on send_join,
simplifies a sync state gate, fixes an `event_type`→`type` field read, and
prepends the create event to invite stripped state.

## What changed vs step 129

**Nothing in `src/` — this directory was a byte-identical copy.** The one
portable hunk (create event first in invite state) is implemented in the
modern chain as part of step 120 (`build_invite_state` starts with
`m.room.create`); the rest has no counterpart here:

| Rust change | C++ translation |
|---|---|
| **Create event first in invite stripped state** | **Covered in step 120** — `build_invite_state` starts with `m.room.create` |
| **`event_type` → `type` in the state-diff member check** | **No counterpart** — this codebase has no state-diff member loop; the port reads `type` everywhere already |
| **Join count/pdu_id ordering + redundant membership write** | **No counterpart** — this codebase's federation join path is a stub without that ordering logic |
| **Sync `pdus_after_since` gate removal** | **No counterpart** — this codebase's simplified sync has no state-hash gate |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit130 && ./build/tests
```
