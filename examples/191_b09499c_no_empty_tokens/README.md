# Step 191 — "fix: don't save empty tokens" (Conduit `b09499c`)

Source: [`timokoesters/conduit@b09499c`](https://github.com/timokoesters/conduit/commit/b09499c) (2021-08-19)

## What changed vs step 190

| Rust change | C++ translation |
|---|---|
| **Don't save empty tokens** | **Translated** — No empty tokens |

## Implementation details

1. **No empty tokens** — Don't save empty tokens

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
