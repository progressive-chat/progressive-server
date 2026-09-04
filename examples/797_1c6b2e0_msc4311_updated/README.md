# Step 797 — msc4311_updated

Source: [`timokoesters/conduit@1c6b2e0`](https://github.com/timokoesters/conduit/commit/1c6b2e0) (2025-09-12)

## What changed vs step 796

| Rust change | C++ translation |
|---|---|
| Updated MSC4311 support to include the create event in the `auth_chain` of all state events. | **Requires federation** — Follows step 532b17a (MSC4311). Updates create event in auth chains. |

## Implementation details

This is an update to the MSC4311 implementation (create event in auth chains):

1. **Membership routes**: Updated to include create event in auth chains
2. **State cache**: Updated to handle create event in auth chains
3. **Event handler**: Modified state resolution to include create event
4. **Utils**: Updated `get_create_event` and related utilities

**Status:** Follows step 532b17a (MSC4311). Requires federation implementation.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```