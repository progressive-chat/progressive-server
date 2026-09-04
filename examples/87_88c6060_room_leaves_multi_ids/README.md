# Step 87 — "Add ability to update room leaves with multiple eventIds" (Conduit `88c6060`)

Source: [`timokoesters/conduit@88c6060`](https://github.com/timokoesters/conduit/commit/88c6060) (2021-02-23)

## What changed vs step 86

| Rust change | C++ translation |
|---|---|
| **Update room leaves with multiple eventIds** | **Partial** — Our `pdu_leaves_replace` only handles single event ID |

## Implementation details

This commit changes the `replace_pdu_leaves` function to accept multiple event IDs instead of a single event ID:

1. **`replace_pdu_leaves` now accepts `&[EventId]`** instead of a single `&EventId`
2. **Clears all existing leaves** for the room, then adds each event ID as a new leaf
3. **Enables multiple `prev_events`** — A PDU can now reference multiple previous events
4. **Updated `append_pdu`** to pass the leaves array

**In our C++ implementation:** Our `pdu_leaves_replace` in data.cpp only clears and adds a single event ID. We would need to update it to accept multiple event IDs.

**Status:** Partially implemented — our `pdu_leaves_replace` only handles single event ID

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
