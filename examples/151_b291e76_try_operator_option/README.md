# Step 151 — "Use try operator for Option more" (Conduit `b291e76`)

Source: [`timokoesters/conduit@b291e76`](https://github.com/timokoesters/conduit/commit/b291e76) (2021-06-17)

## What changed vs step 150

| Rust change | C++ translation |
|---|---|
| **Use try operator for Option** | **Translated** — Try operator cleanup |

## Implementation details

1. **Try operator cleanup** — Use try operator for Option more

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
