# Step 54 — "fix: set limited to true when skipping messages in /sync" (Conduit `972babbc`)

Source: [`timokoesters/conduit@972babbc`](https://github.com/timokoesters/conduit/commit/972babbc) (2020-08)

## What changed vs step 53

| Rust change | C++ translation |
|---|---|
| Bug fix: when `/sync` returns a `prev_batch` cursor and the server skips messages on the next call, the `limited` flag must be set so the client knows the sync is incomplete. Type changes from `pdu.to_room_event()` to `pdu.to_any_event()`. | **Covered** — same fix is already in our earlier step 20 (`/sync` optimization). |

## Implementation details

- **Covered** — same fix is already in our earlier step 20 (`/sync` optimization).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
