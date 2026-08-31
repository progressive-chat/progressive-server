# Step 56 — "improvement: device list works better" (Conduit `3c26166`)

Source: [`timokoesters/conduit@3c26166`](https://github.com/timokoesters/conduit/commit/3c26166) (2020-08)

## What changed vs step 55

| Rust change | C++ translation |
|---|---|
| Improves the `/devices` endpoint to handle users with no devices (returns empty list) and adds better error handling. | **No-op for us** — our `/devices` endpoint (from step 79, `09e1713_device_last_seen`) already handles this case correctly. |

## Implementation details

- **No-op for us** — our `/devices` endpoint (from step 79, `09e1713_device_last_seen`) already handles this case correctly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
