# Step 112 — "No longer use/support a local environment file" (Conduit `ab58609`)

Source: [`timokoesters/conduit@ab58609`](https://github.com/timokoesters/conduit/commit/ab58609) (2021-04-16)

## What changed vs step 111

| Rust change | C++ translation |
|---|---|
| **No local environment file** | **Translated** — Removed env.local |

## Implementation details

1. **No local env file** — No longer use/support a local environment file (debian/env.local removed)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
