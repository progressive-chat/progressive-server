# Step 71 — "improvement: Handle optional device_id field during login" (Conduit `890187e`)

Source: [`timokoesters/conduit@890187e`](https://github.com/timokoesters/conduit/commit/890187e) (2021-01-16)

## What changed vs step 70

| Rust change | C++ translation |
|---|---|
| **Handle optional device_id during login** | **Translated** — Optional device_id in login |

## Implementation details

1. **Optional device_id in login** — Handle missing device_id during login

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
