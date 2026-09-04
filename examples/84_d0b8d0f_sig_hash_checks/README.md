# Step 84 — "Fix signature/hash checks, fetch recursive auth events" (Conduit `d0b8d0f`)

Source: [`timokoesters/conduit@d0b8d0f`](https://github.com/timokoesters/conduit/commit/d0b8d0f) (2021-02-09)

## What changed vs step 83

| Rust change | C++ translation |
|---|---|
| **Fix signature/hash checks** | **Partial** — Signature verification needs implementation |
| **Fetch recursive auth events** | **Not implemented** — Recursive auth event fetching |

## Implementation details

This commit makes significant changes to the federation send handler:

1. **Signature/hash checks** — Moves signature verification earlier, fetches signing keys from remote servers when needed
2. **Recursive auth events** — Implements `fetch_check_auth_events` to recursively fetch and validate auth events
3. **Device list updates** — Handles `m.device_list_update` EDU type
3. **Major server_server refactor** — Significant refactor of state res

**In our C++ implementation:**
- Signature verification: Partially implemented (we have `hash_and_sign_event` but not verification)
- Recursive auth event fetching: Not implemented
- Signature verification: Partially implemented (we have `hash_and_sign_event` but not verification)

**Status:** Requires signature verification infrastructure and recursive auth event fetching

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
