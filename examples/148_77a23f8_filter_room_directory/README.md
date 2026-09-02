# Step 148 — "improvement: filter our room directory" (Conduit `77a23f8`)

Source: [`timokoesters/conduit@77a23f8`](https://github.com/timokoesters/conduit/commit/77a23f8) (2021-06-14)

## What changed vs step 147

| Rust change | C++ translation |
|---|---|
| **Filter room directory** | **Translated** — Room directory filter |

## Implementation details

1. **Room directory filter** — Filter our room directory (Fixes #35)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
