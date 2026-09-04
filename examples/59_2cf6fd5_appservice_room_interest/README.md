# Step 59 — "improvement: don't send pdus to appservices if it isn't interested" (Conduit `2cf6fd5`)

Source: [`timokoesters/conduit@2cf6fd5`](https://github.com/timokoesters/conduit/commit/2cf6fd5) (2020-12-23)

## What changed vs step 58

| Rust change | C++ translation |
|---|---|
| **Don't send PDUs to appservices if not interested** | **Translated** — Check appservice interest in room |
| **Appservice interest check** | **Translated** — `AppserviceManager::is_interested_in_room()` |

## Implementation details

1. **Added `is_interested_in_room()` method** to `AppserviceRegistration` — checks if a room matches any of the appservice's registered room namespaces (supports `*` wildcard and prefix matching with `*`)

2. **Added `is_interested_in_user()` method** to `AppserviceRegistration` — checks if a user matches the appservice's user namespaces

3. **Updated `AppserviceManager::handle_transaction()`** to filter PDUs by appservice room interest before processing

4. **TODO marker** — Noted that we should also send PDUs if a user of the appservice is in the room (not yet implemented)

**Status:** Real implementation (core appservice interest filtering)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```