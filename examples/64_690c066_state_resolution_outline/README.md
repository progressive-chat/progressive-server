# Step 64 — "State resolution outline for /send" (Conduit `690c066`)

Source: [`timokoesters/conduit@690c066`](https://github.com/timokoesters/conduit/commit/690c066) (2020-12-22)

## What changed vs step 63

| Rust change | C++ translation |
|---|---|
| **State resolution outline for /send** | **Requires full state resolution** — Not yet implemented |
| **Major refactor of server_server.rs** | **Requires state resolution infrastructure** — Not yet implemented |
| **Add auth_chain selection** | **Requires state resolution** — Not yet implemented |
| **Add state_ids resolution** | **Requires state resolution** — Not yet implemented |

## Implementation details

This is a massive refactor of the federation `/send` endpoint that implements full state resolution:

1. **State resolution outline** — Implements the full state resolution algorithm for federation events
2. **Auth chain selection** — Selects appropriate auth events for state resolution
3. **State IDs resolution** — Resolves state IDs for the incoming events
4. **State resolution integration** — Uses `state_res` crate for conflict resolution
4. **Forward extremities** — Finds forward extremities for state resolution
4. **Auth checks** — Multiple auth checks at different stages (auth events, state at event, state at forks, current state)
4. **Soft fail handling** — Events that fail auth checks are soft-failed

**Status:** Requires full state resolution infrastructure (state_res crate equivalent) which is not yet implemented in C++. Our federation `/send` handler only has basic PDU storage.

**Note:** This is a major federation feature that requires the state resolution infrastructure from step 93 (short ID system) and step 57 (state resolution basics).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```