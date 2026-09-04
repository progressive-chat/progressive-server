# Step 69 — "Fixing the incoming events algorithm (review with time)" (Conduit `b1ae2bb`)

Source: [`timokoesters/conduit@b1ae2bb`](https://github.com/timokoesters/conduit/commit/b1ae2bb) (2021-01-16)

## What changed vs step 68

| Rust change | C++ translation |
|---|---|
| **Major rewrite of incoming events algorithm** | **Requires full state resolution** — Not yet implemented |
| **Restructured validate_event function** | **Requires full state resolution** — Not yet implemented |
| **Changed auth check flow** | **Requires state resolution** — Not yet implemented |
| **Added forward_extremities function** | **Requires state resolution** — Not yet implemented |
| **Removed signature_and_hash_check function** | **Requires signature verification** — Partially implemented |

## Implementation details

This is a massive rewrite of the federation incoming events algorithm:

1. **Restructured validate_event** — Now returns `(pdu, previous_events)` tuple
2. **Removed manual auth check** — Uses state_res::event_auth::auth_check properly
3. **Added forward_extremities** — Renamed from forward_extremity_ids, includes current state
4. **Removed signature_and_hash_check** — Uses ruma::signatures::verify_event
6. **Added current state check** — Checks auth against current room state (soft fail)
5. **Modified fork state resolution** — Uses forward_extremities with current state
7. **Removed signature_and_hash_check function** — Uses ruma::signatures::verify_event

**Status:** Requires full state resolution infrastructure (state_res, auth event chain fetching, fork state resolution, signature verification) which is not yet implemented in our C++ translation. Our federation handler only has basic send_request.

**Note:** This is a massive federation state resolution refactor that requires:
- Complete state resolution library (state_res)
- Auth event chain fetching and validation
- Forward extremity tracking
- Signature verification (partial - we have hash_and_sign_event but not verification)
- Fork state resolution with current state

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```