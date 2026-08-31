# Step 76 — "improvement: try out multiple servers when joining remote rooms" (Conduit `c5313b3`)

Source: [`timokoesters/conduit@c5313b3`](https://github.com/timokoesters/conduit/commit/c5313b3) (2020-09)

## What changed vs step 75

| Rust change | C++ translation |
|---|---|
| Tries multiple candidate servers when joining a remote room. If `send_join` to the room's home server fails, tries the other servers from the alias response. | Our step 31 (`c5313b3e_multi_server_join`) implements the multi-server fallback. |

## Implementation details

- Our step 31 (`c5313b3e_multi_server_join`) implements the multi-server fallback.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
