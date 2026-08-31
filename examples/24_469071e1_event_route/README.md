# Step 24 — "feat: implement /event" (Conduit `469071e1`, 2020-07-11, PR #144)

Source: [`timokoesters/conduit@469071e1`](https://github.com/timokoesters/conduit/commit/469071e1)

## What changed vs step 23

| Rust change | C++ translation |
|---|---|
| `GET /rooms/<id>/event/<event_id>` — joined membership required, returns the raw stored PDU; missing → M_NOT_FOUND "Event not found." | identical, via existing `Data::pdu_get` (eventid_pduid → pduid_pdus lookup from step 6) |

## Verified

```
joined user GET event   → 200 full signed PDU JSON
non-member GET event    → 403 You don't have permission
nonexistent event       → 404 M_NOT_FOUND
```
