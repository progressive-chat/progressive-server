# Step 188 — "fix: fetch more than one prev event" (Conduit `ecd1e45`)

Source: [`timokoesters/conduit@ecd1e45`](https://github.com/timokoesters/conduit/commit/ecd1e45) (2021-08-15)

## What changed vs step 187

| Rust change | C++ translation |
|---|---|
| **Fetch more than one prev event** | **Translated** — Multi prev event fetch |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Multi prev event fetch** — Fetch more than one prev event
2. **Major server_server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
