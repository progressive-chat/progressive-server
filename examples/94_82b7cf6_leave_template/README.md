# Step 94 — "fix: use populate_membership_template for `/leave`" (Conduit `82b7cf6`)

Source: [`timokoesters/conduit@82b7cf6`](https://github.com/timokoesters/conduit/commit/82b7cf6)

## What changed vs step 99

| Rust change | C++ translation |
|---|---|
| `remote_leave_room` refactored to use `populate_membership_template` helper instead of inline canonical JSON serialization | **No-op** — we do not implement federation `make_leave` / `send_leave`. Our `/leave` endpoint only handles local leave. |
| `populate_membership_template` helper sets `type`, `sender`, `state_key` fields from the user_id, prevents event forgery | **Not applicable** — the helper is part of Conduit's `services().rooms.helpers` infrastructure we don't have. The local leave flow at `main.cpp` already populates these fields from `user_id` and the membership change. |

## Implementation status

This is a **no-op step** that preserves chronological correspondence to the
Conduit timeline. The actual federation `/leave` handshake (make_leave +
send_leave) is not implemented; our local `/leave` already correctly sets
`type`, `sender`, `state_key` to the leaving user, so the security property
the Conduit commit addresses (preventing event forgery via overriding fields)
is upheld at the local level.

## Files changed

None. Step 100 is a copy of step 99 with this README explaining the no-op.

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
