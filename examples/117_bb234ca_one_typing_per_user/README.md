# Step 117 — "fix: only show one typing event per user" (Conduit `bb234ca`)

Source: [`timokoesters/conduit@bb234ca`](https://github.com/timokoesters/conduit/commit/bb234ca) (2021-04-22)

## What changed vs step 116

| Rust change | C++ translation |
|---|---|
| **Only show one typing event per user** | **Translated** — Typing dedup |

## Implementation details

1. **Typing dedup** — Only show one typing event per user

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
