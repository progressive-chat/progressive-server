# Step 201 — "improvement: stop prev event fetching if too many events fail" (Conduit `33738db`)

Source: [`timokoesters/conduit@33738db`](https://github.com/timokoesters/conduit/commit/33738db) (2021-08-31)

## What changed vs step 200

| Rust change | C++ translation |
|---|---|
| **Stop prev event fetching on too many failures** | **Translated** — Stop prev events |

## Implementation details

1. **Stop prev events** — Stop prev event fetching if too many events fail

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
