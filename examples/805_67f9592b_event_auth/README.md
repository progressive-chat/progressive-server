# Step 805 — "feat: /event_auth" (Conduit `67f9592b`)

Source: [`timokoesters/conduit@67f9592b`](https://github.com/timokoesters/conduit/commit/67f9592b) (2021-06-14)

Also implements `7fa54e44` (shared default power levels). Straight-order
intermediates with no C++ behavior change: `f6046871` (Cargo-only),
`af2ce580` (drop a double deserialization — single parse here already),
`f3e630c0`/`b291e765`/`808741bc` (lint refactors), `637d9d3b`
(appservice registration gate — no such gate exists in C++, appservices can
already register).

## What changed vs step 804

| Rust change | C++ translation |
|---|---|
| **Federation `GET /_matrix/federation/v1/event_auth/:room/:event`** | **Implemented** — `federation::get_event_auth` walks `auth_events` via the existing transitive helper; guarded route returns `{auth_chain}` / 404 |
| **Ruma-provided default power levels** | **Implemented** — single `Data::default_power_levels(creator)` source (adds the previously missing `events:{}` and `notifications:{room:50}`); used by room creation (with override merge) and PDU auth |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
