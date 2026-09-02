# Step 213 — "Fix join panic bug" (Conduit `86177fa`)

Source: [`timokoesters/conduit@86177fa`](https://github.com/timokoesters/conduit/commit/86177fa) (2021-11-07)

## What changed vs step 212

| Rust change | C++ translation |
|---|---|
| **Fix join panic bug** | **Translated** — Fix join panic |

## Implementation details

1. **Fix join panic** — Fix join panic bug

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
