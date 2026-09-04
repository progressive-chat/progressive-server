# Step 71 — "improvement: Handle optional device_id field during login" (Conduit `890187e`)

Source: [`timokoesters/conduit@890187e`](https://github.com/timokoesters/conduit/commit/890187e) (2021-01-16)

## What changed vs step 70

| Rust change | C++ translation |
|---|---|
| **Handle optional device_id during login** | **Already implemented** — Uses `value_or(utils::random_string(10))` |

## Implementation details

**Already implemented** — Our login handler in `handlers.cpp` already uses `body.device_id.value_or(utils::random_string(10))` to generate a random device ID when none is provided.

**Status:** Already implemented

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```