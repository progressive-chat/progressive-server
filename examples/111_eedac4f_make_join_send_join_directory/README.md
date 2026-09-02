# Step 111 — "feat: make_join, send_join and /directory" (Conduit `eedac4f`)

Source: [`timokoesters/conduit@eedac4f`](https://github.com/timokoesters/conduit/commit/eedac4f) (2021-04-16)

## What changed vs step 110

| Rust change | C++ translation |
|---|---|
| **make_join** | **Translated** — make_join endpoint |
| **send_join** | **Translated** — send_join endpoint |
| **/directory** | **Translated** — /directory endpoint |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **make_join** — Add make_join federation endpoint
2. **send_join** — Add send_join federation endpoint
3. **/directory** — Add /directory endpoint
4. **Major server_server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
