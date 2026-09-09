# Step 117 — "improvement: optimize room directory" (Conduit `3c3062a3`)

Source: [`timokoesters/conduit@3c3062a3`](https://github.com/timokoesters/conduit/commit/3c3062a3) (2021-04-28)

Straight-order intermediates with no C++ behavior change: `5be5c9e9`
(Cargo-only ruma bump), `c2b72773` (clippy), `2e1d7d12`
(`CanonicalJsonValue` constructor churn — no ruma types in C++).

## What changed vs step 116

| Rust change | C++ translation |
|---|---|
| **Per-room chunks from targeted `room_state_get` instead of full `room_state_full`** | **Implemented** — new `Data::public_room_chunk()`; both directory paths use it (removes the per-room full-state scan, upstream's `TODO: Do not load full state?`) |
| **Real `canonical_alias` / `topic` / `avatar_url` fields** | **Implemented** — read from their state events (previously only `name`, or hardcoded) |
| **Real `world_readable` / `guest_can_join`** | **Implemented** — from `history_visibility == world_readable` / `guest_access == can_join` (previously hardcoded `false`/`true`) |
| **`num_joined_members` from member count** | **Kept** — `room_users()` (sorted by members as before) |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
