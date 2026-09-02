# Step 174 — "improvement: batch inserts for stateids" (Conduit `41ec7cf`)

Source: [`timokoesters/conduit@41ec7cf`](https://github.com/timokoesters/conduit/commit/41ec7cf) (2021-08-03)

## What changed vs step 173

| Rust change | C++ translation |
|---|---|
| **Batch inserts for stateids** | **Translated** — Batch stateids |
| **Major rooms.rs refactor** | **Translated** — Cleaner rooms code |

## Implementation details

1. **Batch stateids** — Batch inserts for stateids
2. **Major rooms refactor** — Major refactor of rooms.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
