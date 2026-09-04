# 2024/2025-tail — "fix: set previous creators to max power level if "upgraded" room doesn't support creator power level" (Conduit `e757a98`)

Source: [`timokoesters/conduit@e757a98`](https://github.com/timokoesters/conduit/commit/e757a98) (2025-09-12)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| When upgrading a room, copies the previous room's creators to the new room's power level (max). | **Requires room upgrades** — Our room upgrade doesn't have this creator power level handling. |

## Implementation details

This fix handles creator power levels during room upgrades:

1. **Fetches old room's create event** to get its room version and rules
2. **Gets old authorization rules** from the previous room's version
3. **Updates power levels** during upgrade:
   - If new room version supports `explicitly_privilege_room_creators`: removes old creators from users map
   - If new version doesn't support it BUT old version did: adds old creators (including `additional_creators`) with max power level (Int::MAX)
   - Handles `users` map properly (creates if empty, removes if empty after changes)

**Status:** Requires room upgrade implementation (step 93+). Our room upgrade doesn't have this creator power level handling.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```