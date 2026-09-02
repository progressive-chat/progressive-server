# Step 203 — "fix: make sure old events don't sneek into the timeline" (Conduit `71341ea`)

Source: [`timokoesters/conduit@71341ea`](https://github.com/timokoesters/conduit/commit/71341ea) (2021-09-03)

## What changed vs step 202

| Rust change | C++ translation |
|---|---|
| **Old events don't sneek into timeline** | **Translated** — No old events in timeline |

## Implementation details

1. **No old events in timeline** — Make sure old events don't sneek into the timeline

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
