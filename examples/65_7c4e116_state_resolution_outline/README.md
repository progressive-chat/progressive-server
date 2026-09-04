# Step 65 — "State resolution outline for /send" (Conduit `7c4e116`)

Source: [`timokoesters/conduit@7c4e116`](https://github.com/timokoesters/conduit/commit/7c4e116) (2021-01-14)

## What changed vs step 64

| Rust change | C++ translation |
|---|---|
| **State resolution outline for /send (cont.)** | **Requires full state resolution** — Not yet implemented |
| **Add forward_extremity_ids, append_state, append_state_soft** | **Stubs added** — Functions added but not implemented |

## Implementation details

This commit adds the missing function stubs referenced in step 64:

1. **`forward_extremity_ids`** — Returns `todo!()`, needs implementation to find forward extremities
2. **`append_state`** — Appends state event to room state (with appservice notification)
3. **`append_state_soft`** — Appends state without updating room state hash (for soft-failed events)

**Status:** Requires full state resolution infrastructure. Our C++ implementation doesn't have these functions yet.

**Note:** This is part of the major federation state resolution refactor that requires the complete state resolution infrastructure from step 93 (short ID system) and step 57 (state resolution basics).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```