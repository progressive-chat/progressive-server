# Step 72 — "Simplify device creation logic during login" (Conduit `762255f`)

Source: [`timokoesters/conduit@762255f`](https://github.com/timokoesters/conduit/commit/762255f) (2021-01-17)

## What changed vs step 71

| Rust change | C++ translation |
|---|---|
| **Simplify device creation logic** | **Translated** — Simplified device creation during login |

## Implementation details

1. **Added `device_exists()` method** to `Data` class to check if a device exists for a user
2. **Updated `login_route`** to use simplified logic:
   - If `device_id` was provided and already exists for the user, just update its token
   - Otherwise create a new device with `device_add()` and `token_replace()`
3. **Simplified logic**: Removed the `create_new_device` flag and explicit iteration

**Status:** Real implementation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```