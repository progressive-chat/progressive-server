# Step 234 — "feat: room_account_data endpoints" (Conduit `e305889`)

Source: [`timokoesters/conduit@e305889`](https://github.com/timokoesters/conduit/commit/e305889) (2021-03)

## What changed vs step 233

| Rust change | C++ translation |
|---|---|
| Feat: room_account_data endpoints. Per-room account data (like tags, settings). 2 files changed. | **Translated** — We have global account_data (step 30). Room-scoped account_data is new. |

## Implementation details

- We have global account_data (step 30). Room-scoped account_data is new.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
