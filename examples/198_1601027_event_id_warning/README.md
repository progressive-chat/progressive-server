# Step 198 — "add warning if calculated event id != requested event id" (Conduit `1601027`)

Source: [`timokoesters/conduit@1601027`](https://github.com/timokoesters/conduit/commit/1601027) (2021-08-28)

## What changed vs step 197

| Rust change | C++ translation |
|---|---|
| **Event id warning** | **Translated** — Event id mismatch warning |

## Implementation details

1. **Event id mismatch warning** — Add warning if calculated event id != requested event id

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
