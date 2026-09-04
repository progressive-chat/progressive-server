# Step 787 — msc4311_create_event_invites

Source: [`timokoesters/conduit@532b17a`](https://github.com/timokoesters/conduit/commit/532b17a) (2025-08-11)

## What changed vs step 786

| Rust change | C++ translation |
|---|---|
| Federation invite/knock includes the create event in `auth_chain` (MSC4311). | **Requires federation** — Our federation doesn't include create event in invite/knock auth chains yet. |

## Implementation details

This commit implements MSC4311 - ensuring the create event is available on invites and knocks:

1. **Federation invite/knock**: Includes the room's create event in the auth chain
2. **Auth chain building**: New logic to include create event when building auth chains for invites/knocks
3. **Utils**: New `get_create_event` utility to fetch the create event

**Status:** Requires federation implementation (step 29+). Our federation doesn't include create event in auth chains for invites/knocks yet.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```