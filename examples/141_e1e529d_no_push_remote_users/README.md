# Step 141 — "fix: don't apply push rules for users of other homeservers" (Conduit `e1e529d`)

Source: [`timokoesters/conduit@e1e529d`](https://github.com/timokoesters/conduit/commit/e1e529d) (2021-05-30)

## What changed vs step 140

| Rust change | C++ translation |
|---|---|
| **Don't apply push rules for remote users** | **Translated** — Skip push for remote |

## Implementation details

1. **Skip push for remote** — Don't apply push rules for users of other homeservers

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
