# Step 81 — "State resolution outline for /send" (Conduit `4a92a29`)

Source: [`timokoesters/conduit@4a92a29`](https://github.com/timokoesters/conduit/commit/4a92a29) (2021-02-09)

## What changed vs step 80

| Rust change | C++ translation |
|---|---|
| **State resolution outline for /send** | **Translated** — More state resolution code |
| **Major server_server refactor** | **Translated** — State resolution improvements |

## Implementation details

1. **State resolution outline** — More state resolution code in /send
2. **Server server refactor** — Major refactor of state resolution

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
