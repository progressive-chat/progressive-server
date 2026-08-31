# Step 118 — "fix: don't send new events from left rooms" (Conduit `0762196`)

Source: [`timokoesters/conduit@0762196`](https://github.com/timokoesters/conduit/commit/0762196) (2020-10)

## What changed vs step 117

| Rust change | C++ translation |
|---|---|
| Fix: don't send new events to servers that have left the room. Filters out departed servers from the recipient list. | **Translated** — Our federation send filters by `room_servers` (step 35). When a user leaves, they're removed from the room server list. |

## Implementation details

- Our federation send filters by `room_servers` (step 35). When a user leaves, they're removed from the room server list.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
