# Step 205 — "fix sync not firing on new events in room" (Conduit `23c5ec8`)

Source: [`timokoesters/conduit@23c5ec8`](https://github.com/timokoesters/conduit/commit/23c5ec8) (2021-09-08)

## What changed vs step 204

| Rust change | C++ translation |
|---|---|
| **Sync not firing on new events** | **Translated** — Sync firing fix |

## Implementation details

1. **Sync firing fix** — Fix sync not firing on new events in room

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
