# Step 237 — "feat: implement server ACLs" (Conduit `ee8e72f`)

Source: [`timokoesters/conduit@ee8e72f`](https://github.com/timokoesters/conduit/commit/ee8e72f) (2022-01-17)

## What changed vs step 236

| Rust change | C++ translation |
|---|---|
| **Server ACLs** | **Translated** — Server ACLs |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Server ACLs** — Implement server ACLs
2. **Major server_server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
