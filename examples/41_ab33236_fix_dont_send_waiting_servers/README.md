# Step 41 — "fix: don't send new requests to servers if we are already waiting" (Conduit `ab33236`)

Source: [`timokoesters/conduit@ab33236`](https://github.com/timokoesters/conduit/commit/ab33236) (2020-10-01)

## What changed vs step 40

| Rust change | C++ translation |
|---|---|
| **Added `waiting_servers` HashSet** to track servers with pending requests | **Translated** — Added `waiting_servers_` unordered_set to track servers with pending federation requests |
| **Refactored event handling** into separate `handle_event` async function | **Translated** — Extracted `handle_federation_event` async method |
| **Only send requests to servers not already waiting** | **Translated** — Check `waiting_servers_` before sending new requests |
| **Used `FuturesUnordered` for concurrent handling** | **Translated** — Used `std::vector<std::future<>>` for concurrent handling |

## Implementation details

1. **Added `waiting_servers_` set** to track servers with pending federation requests
2. **Refactored event handling** into a separate async method `handle_federation_event`
3. **Modified event processing loop** to only send requests to servers not already waiting
3. **Updated federation sending logic** to properly track and wait for responses

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
