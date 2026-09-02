# Step 114 — "fix: don't allow inviting other users (not implemented yet)" (Conduit `e815486`)

Source: [`timokoesters/conduit@e815486`](https://github.com/timokoesters/conduit/commit/e815486) (2021-04-21)

## What changed vs step 113

| Rust change | C++ translation |
|---|---|
| **Don't allow inviting other users** | **Translated** — Disable invite endpoint |

## Implementation details

1. **No invite others** — Don't allow inviting other users (not implemented yet)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
