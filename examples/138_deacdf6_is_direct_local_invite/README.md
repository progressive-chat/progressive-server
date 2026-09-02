# Step 138 — "fix: is_direct for locally invited users" (Conduit `deacdf6`)

Source: [`timokoesters/conduit@deacdf6`](https://github.com/timokoesters/conduit/commit/deacdf6) (2021-05-28)

## What changed vs step 137

| Rust change | C++ translation |
|---|---|
| **is_direct for locally invited users** | **Translated** — is_direct fix |

## Implementation details

1. **is_direct fix** — Fix is_direct for locally invited users

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
