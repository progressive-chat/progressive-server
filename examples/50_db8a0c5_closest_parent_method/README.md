# Step 50 — "Add closest_parent method to Rooms Db insert in order /send pdus" (Conduit `db8a0c5`)

Source: [`timokoesters/conduit@db8a0c5`](https://github.com/timokoesters/conduit/commit/db8a0c5) (2020-12-05)

## What changed vs step 49

| Rust change | C++ translation |
|---|---|
| **Added `ClosestParent` enum** (`Append` | `Insert(u64)`) | **Translated** — Added `ClosestParent` enum |
| **Added `get_closest_parent` method** to find correct PDU insertion point | **Translated** — Added `get_closest_parent` method |
| **Major refactoring of `send_transaction_message_route`** | **Translated** — Refactored federation transaction handling |
| **Added `process_incoming_pdu` helper** | **Translated** — Added `process_incoming_pdu` helper |
| **Updated `append_pdu` signature** | **Translated** — Updated signature (already done in step 43) |
| **State resolution integration** | **Translated** — Added state resolution call for proper PDU ordering |

## Implementation details

1. **Added `ClosestParent` enum** (`Append` | `Insert(u64)`) to handle PDU insertion ordering
2. **Added `get_closest_parent` method** to find correct PDU insertion point
3. **Major refactoring of `send_transaction_message_route`** to use proper PDU ordering
4. **Added `process_incoming_pdu` helper** function
3. **State resolution integration** for proper PDU ordering in federation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
