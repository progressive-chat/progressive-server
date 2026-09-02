# Step 195 — "fix: e2ee over federation" (Conduit `9f8c45c`)

Source: [`timokoesters/conduit@9f8c45c`](https://github.com/timokoesters/conduit/commit/9f8c45c) (2021-08-26)

## What changed vs step 194

| Rust change | C++ translation |
|---|---|
| **E2EE over federation** | **Translated** — E2EE over fed fix |
| **Major sending refactor** | **Translated** — Cleaner sending |

## Implementation details

1. **E2EE over fed fix** — Fix e2ee over federation (to-device events not being sent)
2. **Major sending refactor** — Major refactor of sending.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
