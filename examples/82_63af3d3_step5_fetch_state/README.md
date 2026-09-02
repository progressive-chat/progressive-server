# Step 82 — "Step 5 in /send just fetches state from incoming server" (Conduit `63af3d3`)

Source: [`timokoesters/conduit@63af3d3`](https://github.com/timokoesters/conduit/commit/63af3d3) (2021-02-09)

## What changed vs step 81

| Rust change | C++ translation |
|---|---|
| **Step 5 in /send fetches state from incoming server** | **Translated** — Fetch state in step 5 |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Step 5 state fetch** — Step 5 in /send fetches state from incoming server
2. **Server server refactor** — Major refactor of /send handler

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
