# Step 716 — "Avatars for sliding sync DMs" (Conduit `d82c26f`)

Source: [`timokoesters/conduit@d82c26f`](https://github.com/timokoesters/conduit/commit/d82c26f) (2023-08)

## What changed vs step 715

| Rust change | C++ translation |
|---|---|
| Avatars for sliding sync DMs. Sliding sync avatar support for direct messages. 4 files changed. | **Requires step 670/689/690** — Adds avatar support for DMs in sliding sync. |

## Implementation details

This Conduit commit adds avatar support for sliding sync DMs:

1. **DM avatars**: For DM rooms (1:1), uses the other user's avatar as room avatar
2. **Heroes logic**: For DMs, extracts member display names and avatars (up to 5)
3. **Room name fallback**: Uses hero names when room has no name
4. **Avatar fallback**: Uses hero avatar for DM rooms
5. **New `get_avatar` method**: Fetches `m.room.avatar` state event

**Status:** Requires steps 670/689/690 (sliding sync). Our `get_room_name` in step 670 already has similar logic.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```