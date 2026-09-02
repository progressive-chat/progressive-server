# Step 47 — "fix: don't send new events from left rooms" (Conduit `0762196`)

Source: [`timokoesters/conduit@0762196`](https://github.com/timokoesters/conduit/commit/0762196) (2020-10-27)

## What changed vs step 46

| Rust change | C++ translation |
|---|---|
| **Fixed member event content extraction** using `.1` to get content from tuple | **Translated** — Updated member event handling to properly extract content from `(IVec, PduEvent)` tuples |
| **Fixed sync logic** to not send new events from left rooms | **Translated** — Updated sync logic to skip rooms user has left |
| **Changed `room_state_get`** to return `(IVec, PduEvent)` tuple | **Translated** — Updated `room_state_get` to return pair of pdu_id and event |
| **Fixed sync logic for left rooms** | **Translated** — Updated sync to properly handle left rooms |

## Implementation details

1. **Member event content extraction**: Fixed content extraction from `(IVec, PduEvent)` tuples returned by `room_state_get`
2. **Sync logic for left rooms**: Updated sync to properly handle rooms the user has left
3. **`room_state_get` signature**: Changed to return `(IVec, PduEvent)` instead of just `PduEvent`
4. **Sync logic for left rooms**: Properly handles left rooms in sync by not sending new events

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
