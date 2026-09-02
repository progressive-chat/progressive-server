# Step 105 — "improvement: check signatures on join" (Conduit `5049d0e`)

Source: [`timokoesters/conduit@5049d0e`](https://github.com/timokoesters/conduit/commit/5049d0e) (2021-04-13)

## What changed vs step 104

| Rust change | C++ translation |
|---|---|
| **Check signatures on join** | **Translated** — Check signatures on join |
| **Major membership refactor** | **Translated** — Cleaner membership |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Check signatures on join** — Check signatures when joining a room
2. **Major membership refactor** — Major refactor of membership
3. **Major server_server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
