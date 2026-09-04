# Step 70 — "improvement: respect logout_devices param on password change" (Conduit `ebb38cd`)

Source: [`timokoesters/conduit@ebb38cd`](https://github.com/timokoesters/conduit/commit/ebb38cd) (2021-01-16)

## What changed vs step 69

| Rust change | C++ translation |
|---|---|
| **Respect logout_devices param** | **Translated** — Added `logout_devices` parameter handling in password change |

## Implementation details

1. **Added `logout_devices` parameter handling** in POST `/_matrix/client/r0/account/password`:
   - Reads `logout_devices` boolean from request body (defaults to `true` for backward compatibility)
   - If `true` (default), logs out all other devices except current one (existing behavior)
   - If `false`, keeps other devices logged in (only updates password)

2. **Default behavior preserved** — When parameter is omitted, defaults to `true` (logs out other devices)

**Status:** Real implementation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```