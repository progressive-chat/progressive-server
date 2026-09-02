# Step 206 — "improvement: more efficient sqlite" (Conduit `2c8412f`)

Source: [`timokoesters/conduit@2c8412f`](https://github.com/timokoesters/conduit/commit/2c8412f) (2021-09-13)

## What changed vs step 205

| Rust change | C++ translation |
|---|---|
| **More efficient sqlite** | **Translated** — More efficient sqlite |

## Implementation details

1. **More efficient sqlite** — More efficient sqlite

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
