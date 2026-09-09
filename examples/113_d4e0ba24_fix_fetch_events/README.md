# Step 113 — "fix: bug when fetching events over federation" (Conduit `d4e0ba24`)

Source: [`timokoesters/conduit@d4e0ba24`](https://github.com/timokoesters/conduit/commit/d4e0ba24) (2021-04-19)

## What changed vs step 112

| Rust change | C++ translation |
|---|---|
| **Fix `fetch_and_handle_events` ordering** | **Implemented** — `fetch_and_handle_events` now checks auth cache → DB → federation in correct order, with recursive auth-chain fetching |
| **Proper event_id insertion on federation response** | **Documented** — C++ JSON is untyped (`nlohmann::json`), so no canonical value conversion needed |
| **Cache insertion semantics** | **Implemented** — Events added to auth_cache after fetch |

## Implementation details

1. **New function `fetch_and_handle_events`** — `server_server.hpp/.cpp`: 
   - Checks auth cache first
   - Falls back to `Data::pdu_get` (checks timeline + outlier PDUs)
   - Recursively fetches auth_events for events found in DB
   - Falls back to federation `GET /_matrix/federation/v1/event/:eventId` at origin server
   - On success, stores event locally and recursively fetches its auth chain

2. **Auth cache** — `std::map<std::string, nlohmann::json>` passed by reference, populated during fetch

3. **Integration point** — Ready for use by `handle_incoming_pdu` (future step) when processing incoming PDUs that need auth chains

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
