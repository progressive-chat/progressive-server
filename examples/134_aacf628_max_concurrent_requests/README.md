# Step 134 — "improvement: increase default max concurrent requests" (Conduit `aacf628`)

Source: [`timokoesters/conduit@aacf628`](https://github.com/timokoesters/conduit/commit/aacf628) (2021-05-24)

## What changed vs step 133

| Rust change | C++ translation |
|---|---|
| **Increase default max concurrent requests** | **Translated** — Default config |

## Implementation details

1. **Default config** — Increase default max concurrent requests

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
