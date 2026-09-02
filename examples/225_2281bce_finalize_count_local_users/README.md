# Step 225 — "Finalize count_local_users function" (Conduit `2281bce`)

Source: [`timokoesters/conduit@2281bce`](https://github.com/timokoesters/conduit/commit/2281bce) (2021-12-26)

## What changed vs step 224

| Rust change | C++ translation |
|---|---|
| **Finalize count_local_users** | **Translated** — Finalize count_local_users |

## Implementation details

1. **Finalize count_local_users** — Finalize count_local_users function

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
