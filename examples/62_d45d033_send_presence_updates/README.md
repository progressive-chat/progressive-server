# Step 62 — "fix: send presence updates when going offline" (Conduit `d45d033`)

Source: [`timokoesters/conduit@d45d033`](https://github.com/timokoesters/conduit/commit/d45d033) (2021-01-10)

## What changed vs step 61

| Rust change | C++ translation |
|---|---|
| **Send presence updates when going offline** | **Requires EDU infrastructure** — Not yet implemented |
| **EDU handling improvements** | **Requires EDU infrastructure** — Not yet implemented |

## Implementation details

This commit modifies the EDU (Ephemeral Data Unit) handling to send presence updates when a user goes offline. The key changes:

1. **Removes old presence update** when user goes offline
2. **Inserts new presence update** with offline status
3. **Bug noted**: Conduit sends presence updates every 5 minutes even if user is already offline (not fixed in this commit)

**Status:** Requires EDU infrastructure (presence, typing, receipts EDUs) which is not yet implemented in our C++ translation. This would require:
- EDU database trees (`presenceid_user`, `userid_lastpresenceupdate`)
- EDU processing in `/sync` and federation
- Presence event generation and delivery

**Note:** The remaining bug (sending presence updates every 5 minutes for already offline users) is not fixed in this commit.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```