# Step 19 — "improvement: /members route" (Conduit `7031240a`, 2020-06-14)

Source: [`timokoesters/conduit@7031240a`](https://github.com/timokoesters/conduit/commit/7031240a)

## What changed vs step 18

| Rust change | C++ translation |
|---|---|
| GET /rooms/<id>/members now requires joined membership (`is_joined` check, was commented out) | enforced — non-members get 403 |
| returns real member events via `room_state_type(RoomMember)` (was empty Vec) | `Data::room_state_type` prefix-scans roomstateid_pdu by type |

## Verified

```
bob (joined)   → chunk with both member events (incl. unsigned.prev_content)
carol (absent) → 403 You don't have permission to view this room.
```
