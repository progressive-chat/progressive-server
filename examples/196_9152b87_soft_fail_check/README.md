# Step 196 — "fix: wrong soft fail check, too many events in /sync state response" (Conduit `9152b87`)

Source: [`timokoesters/conduit@9152b87`](https://github.com/timokoesters/conduit/commit/9152b87) (2021-08-26)

## What changed vs step 195

| Rust change | C++ translation |
|---|---|
| **Wrong soft fail check** | **Translated** — Soft fail check fix |
| **Too many events in /sync state** | **Translated** — Sync state response |

## Implementation details

1. **Soft fail check fix** — Fix wrong soft fail check
2. **Sync state response** — Too many events in /sync state response

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
