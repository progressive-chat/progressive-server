# Step 143 — "create media folder in init" (Conduit `affa124`)

Source: [`timokoesters/conduit@affa124`](https://github.com/timokoesters/conduit/commit/affa124) (2021-06-09)

## What changed vs step 142

| Rust change | C++ translation |
|---|---|
| **Create media folder in init** | **Translated** — Media folder init |

## Implementation details

1. **Media folder init** — Create media folder in init

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
