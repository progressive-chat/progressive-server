# Step 376 — "Add "database_memory_usage" AdminCommand" (Conduit `ff24387`)

Source: [`timokoesters/conduit@ff24387`](https://github.com/timokoesters/conduit/commit/ff24387) (2022-01)

## What changed vs step 375

| Rust change | C++ translation |
|---|---|
| Add 'database_memory_usage' AdminCommand. Admin command to check DB memory usage. 2 files changed. | **Translated** — Our admin commands (step 60) don't have this. New admin command for memory reporting. |

## Implementation details

- Our admin commands (step 60) don't have this. New admin command for memory reporting.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
