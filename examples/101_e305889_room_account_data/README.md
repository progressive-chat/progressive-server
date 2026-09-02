# Step 101 — "feat: room_account_data endpoints" (Conduit `e305889`)

Source: [`timokoesters/conduit@e305889`](https://github.com/timokoesters/conduit/commit/e305889) (2021-03-24)

## What changed vs step 100

| Rust change | C++ translation |
|---|---|
| **room_account_data endpoints** | **Translated** — Room account data endpoints |

## Implementation details

1. **Room account data** — Add room_account_data endpoints for setting/getting account data per room

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
