# Step 175 — "improvement: better auth chain calculation" (Conduit `fce2236`)

Source: [`timokoesters/conduit@fce2236`](https://github.com/timokoesters/conduit/commit/fce2236) (2021-08-03)

## What changed vs step 174

| Rust change | C++ translation |
|---|---|
| **Better auth chain calculation** | **Translated** — Better auth chain |

## Implementation details

1. **Better auth chain** — Better auth chain calculation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
