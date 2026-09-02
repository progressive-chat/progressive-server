# Step 92 — "fix: multiple federation/pusher fixes" (Conduit `44425a9`)

Source: [`timokoesters/conduit@44425a9`](https://github.com/timokoesters/conduit/commit/44425a9) (2021-03-16)

## What changed vs step 91

| Rust change | C++ translation |
|---|---|
| **Multiple federation/pusher fixes** | **Translated** — Federation/pusher fixes |
| **Major error.rs cleanup** | **Translated** — Removed unused error code |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Federation/pusher fixes** — Multiple federation and pusher fixes
2. **Error cleanup** — Removed unused error code
3. **Server server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
