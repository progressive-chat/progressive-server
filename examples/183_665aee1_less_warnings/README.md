# Step 183 — "less warnings" (Conduit `665aee1`)

Source: [`timokoesters/conduit@665aee1`](https://github.com/timokoesters/conduit/commit/665aee1) (2021-08-12)

## What changed vs step 182

| Rust change | C++ translation |
|---|---|
| **Less warnings** | **Translated** — Less warnings |

## Implementation details

1. **Less warnings** — Less warnings

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
