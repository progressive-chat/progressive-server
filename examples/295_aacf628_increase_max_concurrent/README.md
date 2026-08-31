# Step 295 — "improvement: increase default max concurrent requests" (Conduit `aacf628`)

Source: [`timokoesters/conduit@aacf628`](https://github.com/timokoesters/conduit/commit/aacf628) (2021-05)

## What changed vs step 294

| Rust change | C++ translation |
|---|---|
| Improvement: increase default max concurrent requests. Allow more simultaneous connections. 4 files changed. | **Translated** — Our server uses httplib which handles concurrency. Config option for max connections would be new. |

## Implementation details

- Our server uses httplib which handles concurrency. Config option for max connections would be new.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
