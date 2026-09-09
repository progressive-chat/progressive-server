# Step 120 — "fix: unauthorized pdus will be responded to with FORBIDDEN" (Conduit `989d843c`)

Source: [`timokoesters/conduit@989d843c`](https://github.com/timokoesters/conduit/commit/989d843c) (2021-05-21)

Straight-order intermediates folded in: `90cd11d8` (invite auth failure →
`Forbidden`), `c1b2b468` (bounds-safe header slicing), `3e2f742f` (create
event first in invite state), `1b42770a` (request-size warning — no such
config in C++).

## What changed vs step 119

| Rust change | C++ translation |
|---|---|
| **Unauthorized PDU builds → `Forbidden`** | **Already compliant** — every user-facing auth failure (`pdu_append`/`room_join` false in message, state, join, invite routes) already returns 403 `M_FORBIDDEN`; audited, no change needed |
| **Invite auth failure → `Forbidden` (`90cd11d8`)** | **Already compliant** — invite routes map failure to 403; documented |
| **Bounds-safe header slicing (`c1b2b468`)** | **Already safe** — `extract_token` and the federation verifier guard prefix length before slicing; documented |
| **Verbose PDU warn reverted to silent skip** | **Implemented** — the `f62258ba` warn added in step 119 is reverted, exactly like upstream did 9 days later |
| **Richer invalid-PDU log context** | **Implemented** — malformed send_join PDUs log `[warn] Invalid PDU in server response: <head>…: <what>` and are skipped (also closes an uncaught-`get()` throw in the handler) |
| **`3e2f742f`: create event first in invite state** | **Implemented** — `build_invite_state` now starts with `m.room.create` (remaining `type`-vs-`event_type` hunks don't apply: C++ reads `type` everywhere already) |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
