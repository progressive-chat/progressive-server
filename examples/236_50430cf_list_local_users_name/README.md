# Step 236 — "Name function after command: list_local_users" (Conduit `50430cf`)

Source: [`timokoesters/conduit@50430cf`](https://github.com/timokoesters/conduit/commit/50430cf) (2022-01-16)

## What changed vs step 235

| Rust change | C++ translation |
|---|---|
| **list_local_users function name** | **Translated** — list_local_users name |

## Implementation details

1. **list_local_users name** — Name function after command: list_local_users

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
