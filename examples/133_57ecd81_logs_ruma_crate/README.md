# Step 133 — "fix: logs for ruma crate" (Conduit `57ecd81`)

Source: [`timokoesters/conduit@57ecd81`](https://github.com/timokoesters/conduit/commit/57ecd81) (2021-05-24)

## What changed vs step 132

| Rust change | C++ translation |
|---|---|
| **Logs for ruma crate** | **Translated** — Ruma logging |

## Implementation details

1. **Ruma logging** — Fix logs for ruma crate

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
