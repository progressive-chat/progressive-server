# Step 700 — "Log the room ID, event ID, PDU, and event type where possible" (Conduit `cc5dcce`)

Source: [`timokoesters/conduit@cc5dcce`](https://github.com/timokoesters/conduit/commit/cc5dcce) (2023-07)

## What changed vs step 699

| Rust change | C++ translation |
|---|---|
| Log the room ID, event ID, PDU, and event type where possible. Enhanced event logging. 4 files changed. | **Translated** — Our event logging (step 8) includes room/event IDs. This adds PDU and event type. |

## Implementation details

- Our event logging (step 8) includes room/event IDs. This adds PDU and event type.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
