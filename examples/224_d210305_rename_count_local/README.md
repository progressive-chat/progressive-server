# Step 224 — "Rename/Add count methods to count_local_users" (Conduit `d210305`)

Source: [`timokoesters/conduit@d210305`](https://github.com/timokoesters/conduit/commit/d210305) (2021-12-25)

## What changed vs step 223

| Rust change | C++ translation |
|---|---|
| **Rename count methods** | **Translated** — Rename count methods |

## Implementation details

1. **Rename count methods** — Rename/Add count methods to count_local_users

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
