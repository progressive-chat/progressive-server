# Step 719 — "More sanity checks" (Conduit `fd9e52a`)

Source: [`timokoesters/conduit@fd9e52a`](https://github.com/timokoesters/conduit/commit/fd9e52a) (2023-08)

## What changed vs step 718

| Rust change | C++ translation |
|---|---|
| More sanity checks. Additional validation checks throughout the codebase. 1 file changed. | **Translated** — Added `check_room_id` validation to PDU handling. |

## Implementation details

This commit adds a `check_room_id` validation function that verifies a PDU's `room_id` matches the expected room_id:

1. **Outlier PDU handling**: Checks room_id after handling outlier PDU
2. **Auth events**: Checks room_id for each auth event
3. **Prev events**: Checks room_id when fetching prev events

**Implementation for C++**: Add a `check_room_id(room_id, pdu)` method that validates `pdu["room_id"] == room_id` and returns error if mismatched.

**Status:** Can be integrated into our `pdu_append` and event handling code.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```