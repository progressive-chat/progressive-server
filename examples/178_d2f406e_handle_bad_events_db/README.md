# Step 178 — "fix: handle bad events in db better" (Conduit `d2f406e`)

Source: [`timokoesters/conduit@d2f406e`](https://github.com/timokoesters/conduit/commit/d2f406e) (2021-08-08)

## What changed vs step 177

| Rust change | C++ translation |
|---|---|
| **Handle bad events in DB** | **Translated** — Better bad events |

## Implementation details

1. **Better bad events** — Handle bad events in DB better

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
