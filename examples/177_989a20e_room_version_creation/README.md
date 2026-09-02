# Step 177 — "Support creating rooms with a version" (Conduit `989a20e`)

Source: [`timokoesters/conduit@989a20e`](https://github.com/timokoesters/conduit/commit/989a20e) (2021-08-07)

## What changed vs step 176

| Rust change | C++ translation |
|---|---|
| **Support room version creation** | **Translated** — Room version creation |

## Implementation details

1. **Room version creation** — Support creating rooms with a version

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
