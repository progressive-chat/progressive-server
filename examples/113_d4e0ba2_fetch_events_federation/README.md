# Step 113 — "fix: bug when fetching events over federation" (Conduit `d4e0ba2`)

Source: [`timokoesters/conduit@d4e0ba2`](https://github.com/timokoesters/conduit/commit/d4e0ba2) (2021-04-19)

## What changed vs step 112

| Rust change | C++ translation |
|---|---|
| **Bug fix: fetching events over federation** | **Translated** — Event fetch fix |

## Implementation details

1. **Event fetch fix** — Fix bug when fetching events over federation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
