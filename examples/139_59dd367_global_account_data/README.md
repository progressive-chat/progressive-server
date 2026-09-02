# Step 139 — "fix: putting global account data works now" (Conduit `59dd367`)

Source: [`timokoesters/conduit@59dd367`](https://github.com/timokoesters/conduit/commit/59dd367) (2021-05-29)

## What changed vs step 138

| Rust change | C++ translation |
|---|---|
| **Putting global account data works** | **Translated** — Global account data fix |

## Implementation details

1. **Global account data fix** — Putting global account data works now

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
