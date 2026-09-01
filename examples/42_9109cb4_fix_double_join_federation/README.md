# Step 42 — "fix: double join over federation" (Conduit `9109cb4`)

Source: [`timokoesters/conduit@9109cb4`](https://github.com/timokoesters/conduit/commit/9109cb4) (2020-10-17)

## What changed vs step 41

| Rust change | C++ translation |
|---|---|
| **Added `content` field to `join_event_stub`** with member content | **Translated** — Added content field to join event stub |
| **Added `event_id` back to join event stub** | **Translated** — Added event_id back to join event |
| **Uses `PduEvent::convert_to_outgoing_federation_event`** instead of raw value | **Translated** — Uses proper conversion to outgoing federation event |
| **Adds join event to `state_events`** to prevent duplicate processing | **Translated** — Added join event to state events |
| **Adds join event to `event_map`** to prevent duplicate processing | **Translated** — Added join event to event map |
| **Fixed error message** from "Invalid redaction event content" to "Invalid member event content" | **Translated** — Fixed error message |

## Implementation details

1. **Fixed double join over federation** by ensuring the join event has all required fields before sending
2. **Added content to join event stub** with member content (membership, displayname, avatar_url)
3. **Added event_id back** to the join event stub so it can be properly signed
4. **Added join event to state_events and event_map** to prevent duplicate processing

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
