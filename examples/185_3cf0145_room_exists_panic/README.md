# Step 185 — "fix: room exists panic" (Conduit `3cf0145`)

Source: [`timokoesters/conduit@3cf0145`](https://github.com/timokoesters/conduit/commit/3cf0145) (2021-08-14)

## What changed vs step 184

| Rust change | C++ translation |
|---|---|
| **Room exists panic** | **Translated** — Room exists panic fix |

## Implementation details

1. **Room exists panic fix** — Fix room exists panic

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
