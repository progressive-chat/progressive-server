# Step 60 — "fix: rare state races" (Conduit `df16b2b`)

Source: [`timokoesters/conduit@df16b2b`](https://github.com/timokoesters/conduit/commit/df16b2b) (2020-12-31)

## What changed vs step 59

| Rust change | C++ translation |
|---|---|
| **Fix rare state races** | **Already implemented in step 57** — State resolution ordering prevents races |
| **State event handling improvements** | **Already implemented in step 57** — append_state_pdu called after pdu_append |

## Implementation details

This Conduit commit fixed a race condition in state resolution by:

1. **Moving `roomid_statehash` insert** from `append_to_state` to a separate `set_room_state` method
2. **Calling `set_room_state` AFTER `append_pdu`** to ensure the PDU exists before the state hash is updated
3. **Preventing race condition** where state could reference a PDU that doesn't exist yet

**In our C++ implementation (step 57):** We already call `append_state_pdu()` AFTER inserting the PDU in `pdu_append`, which achieves the same race-free ordering. The state resolution trees (`stateid_pduid`, `pduid_statehash`, `roomid_statehash`) are updated atomically after the PDU is stored.

**Status:** Already implemented in step 57 (f12fbca).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```