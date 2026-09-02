# Step 163 — "fix: e2ee verification" (Conduit `8c44312`)

Source: [`timokoesters/conduit@8c44312`](https://github.com/timokoesters/conduit/commit/8c44312) (2021-07-14)

## What changed vs step 162

| Rust change | C++ translation |
|---|---|
| **E2EE verification fix** | **Translated** — E2EE verification |

## Implementation details

1. **E2EE verification** — Fix e2ee verification

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
