# Step 64 — "State resolution outline for /send" (Conduit `690c066`)

Source: [`timokoesters/conduit@690c066`](https://github.com/timokoesters/conduit/commit/690c066) (2020-12-22)

## What changed vs step 63

| Rust change | C++ translation |
|---|---|
| **State resolution outline for /send** | **Translated** — State resolution in send_join |
| **Major refactor of server_server.rs** | **Translated** — State resolution in /send |
| **Add auth_chain selection** | **Translated** — Auth chain selection in /send |
| **Add state_ids resolution** | **Translated** — State IDs resolution in /send |

## Implementation details

1. **State resolution in /send** — Major refactor of /send endpoint
2. **Auth chain selection** — Select appropriate auth chain for state
3. **State IDs resolution** — Resolve state IDs during /send
4. **Major server_server refactor** — Restructured /send handler

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
