# Step 68 — "Use the auth_events for step 6, WIP forward_extremity_ids fn" (Conduit `96dc6be`)

Source: [`timokoesters/conduit@96dc6be`](https://github.com/timokoesters/conduit/commit/96dc6be) (2021-01-15)

## What changed vs step 67

| Rust change | C++ translation |
|---|---|
| **Use auth_events for step 6** | **Requires state resolution infrastructure** — Not yet implemented |
| **WIP forward_extremity_ids fn** | **Requires state resolution infrastructure** — Not yet implemented |

## Implementation details

This Conduit commit adds significant state resolution infrastructure for federation:

1. **Uses auth_events for step 6 of state resolution** — The incoming PDU's auth events are used to build the auth cache
2. **Implements forward_extremity_ids function** — Finds fork states by gathering forward extremities
3. **Adds fetch_check_auth_events function** — DFS-based auth event chain validation
4. **Adds forward_extremity_ids function** — Finds fork states by gathering forward extremities and fetching missing state

**Status:** Requires full state resolution infrastructure (state_res, auth event chain fetching, fork state resolution) which is not yet implemented in our C++ translation. The federation send handler in server_server.cpp only has basic send_request functionality.

**Note:** This is a major federation state resolution feature that requires the state resolution infrastructure from steps 67 (outlier/signing key trees) and 57 (state resolution basics).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```