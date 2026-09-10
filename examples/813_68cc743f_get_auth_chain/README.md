# Step 813 — "fix: use get_auth_chain method more often" (Conduit `68cc743f`)

Source: [`timokoesters/conduit@68cc743f`](https://github.com/timokoesters/conduit/commit/68cc743f) (2021-07-20)

Upstream replaces a hand-rolled auth-chain todo-set walk in
`create_join_event_route` with the shared `get_auth_chain()` helper
(transitive auth-event ids of the state ids, missing events warned about
and skipped).

## What changed vs step 812

| Rust change | C++ translation |
|---|---|
| **Shared `get_auth_chain()` helper, used at the join path** | **Implemented** — `federation::get_auth_chain(db, starting_events)` (`src/server_server.*`): iterative with a visited set (additionally cycle-safe), same seed-excluded/missing-skipped semantics |
| **`/state_ids` endpoint uses the helper** | **Implemented** — `get_room_state_ids()` drops its hand-rolled walk for the helper, seeded with the state ids exactly like upstream |
| **`/state_ids` route uses the helper** | **Implemented** — the route previously fetched full PDU objects via `federation_auth_chain()` only to extract their ids; now calls the ids helper directly |
| **`sync.rs` hunk** | **No counterpart** — pure reformatting (`.transpose()?.transpose()?` split across lines), no behavior change |

Covered on the way here (no step needed): `d76e95e8` (drop the leftover
`sled_cache_capacity_bytes` key — step 812 already has a single unified
`db_cache_capacity_mb`); skipped per project rules: `eaa4c776` (CI),
`9de32ae1` (toolchain), `b1993421` (Windows/sqlite-only signals),
`2babff1e` (CI), `cdd01262` (issue templates), `faa283d3` (rocket style),
`d253f923` (sqlite-only), all merges.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit813
```
