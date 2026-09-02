# Step 132 — "fix: too many syncs" (Conduit `9b77eb7`)

Source: [`timokoesters/conduit@9b77eb7`](https://github.com/timokoesters/conduit/commit/9b77eb7) (2021-05-22)

## What changed vs step 131

| Rust change | C++ translation |
|---|---|
| **Too many syncs** | **Translated** — Sync rate limiting |

## Implementation details

1. **Sync rate limiting** — Fix too many syncs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
