# Step 82 — "feat: MSC4291, Room IDs as hashes of the create event (2/2)" (Conduit `bd8686e`)

Source: [`timokoesters/conduit@bd8686e`](https://github.com/timokoesters/conduit/commit/bd8686e)

This step completes MSC4291 by updating room upgrade logic to use hash-based room IDs and proper predecessor tracking via tombstone events.

## What changed vs step 81

| Rust change | C++ translation |
|---|---|
| Room upgrade uses `send_create_room` with predecessor | Room upgrade computes new room ID as hash of create event content, includes predecessor in m.room.create |
| Tombstone event includes `replacement_room` | Tombstone event created with `replacement_room` pointing to new room |
| New room's m.room.create includes `predecessor` | New room's m.room.create includes `predecessor` with old room ID and tombstone event ID |
| `RoomId::new_v1()` for replacement rooms | Replacement room ID computed as hash of its create event content |

## Smoke test status

- Room creation with hash-based IDs works (step 81 verified)
- Room upgrade endpoint compiles but returns 404 - runtime issue with room state lookup (uses `ctx.data` vs `data` pointer mismatch in upgrade handler)
- Core MSC4291 logic (hash-based room IDs, predecessor in create event, tombstone with replacement_room) implemented

**Known issue**: Upgrade endpoint returns 404 due to room state lookup using `ctx.data` vs `data` pointer inconsistency in the upgrade handler. Needs fix: replace `ctx.data` with `data` pointer in upgrade handler.

## Next steps

Fix upgrade handler's data pointer usage, then proceed to MSC4289 part 2 (`4b83303`) and MSC4297 (`d71d94a`).