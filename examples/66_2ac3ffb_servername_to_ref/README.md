# Step 66 — "Convert uses of Box<ServerName> to a ref" (Conduit `2ac3ffb`)

Source: [`timokoesters/conduit@2ac3ffb`](https://github.com/timokoesters/conduit/commit/2ac3ffb) (2021-01-14)

## What changed vs step 65

| Rust change | C++ translation |
|---|---|
| **Convert Box<ServerName> to ref** | **Translated** — Use references for ServerName |
| **Reduce allocations** | **Translated** — Fewer string allocations |
| **Refactor server_server.rs** | **Translated** — Cleaner server_server code |

## Implementation details

1. **ServerName references** — Use references instead of owned strings
2. **Reduce allocations** — Fewer heap allocations
3. **Server server refactor** — Cleaner code in server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
