# Step 157 — "fix errors introduced by rebase" (Conduit `f25f61d`)

Source: [`timokoesters/conduit@f25f61d`](https://github.com/timokoesters/conduit/commit/f25f61d) (2021-07-01)

## What changed vs step 156

| Rust change | C++ translation |
|---|---|
| **Fix rebase errors** | **Translated** — Rebase error fixes |

## Implementation details

1. **Rebase error fixes** — Fix errors introduced by rebase

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
