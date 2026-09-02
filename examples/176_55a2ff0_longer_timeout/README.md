# Step 176 — "improvement: longer timeout, more descriptive errors" (Conduit `55a2ff0`)

Source: [`timokoesters/conduit@55a2ff0`](https://github.com/timokoesters/conduit/commit/55a2ff0) (2021-08-04)

## What changed vs step 175

| Rust change | C++ translation |
|---|---|
| **Longer timeout** | **Translated** — Longer timeout |
| **More descriptive errors** | **Translated** — Better error messages |

## Implementation details

1. **Longer timeout** — Longer timeout
2. **Better error messages** — More descriptive errors

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
