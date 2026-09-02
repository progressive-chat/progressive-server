# Step 210 — "Always send device_one_time_keys_count, fixing #178" (Conduit `d996d1b`)

Source: [`timokoesters/conduit@d996d1b`](https://github.com/timokoesters/conduit/commit/d996d1b) (2021-10-15)

## What changed vs step 209

| Rust change | C++ translation |
|---|---|
| **Always send device_one_time_keys_count** | **Translated** — One-time keys count |

## Implementation details

1. **One-time keys count** — Always send device_one_time_keys_count (fixes #178)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
