# Step 58 — "improvement: better warnings when server is unreachable" (Conduit `fb9bd34`)

Source: [`timokoesters/conduit@fb9bd34`](https://github.com/timokoesters/conduit/commit/fb9bd34) (2020-12-23)

## What changed vs step 57

| Rust change | C++ translation |
|---|---|
| **Better warnings when server is unreachable** | **Translated** — Improved error messages |

## Implementation details

1. **Better error messages** — Clearer warnings for unreachable servers

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
