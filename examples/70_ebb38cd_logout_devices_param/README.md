# Step 70 — "improvement: respect logout_devices param on password change" (Conduit `ebb38cd`)

Source: [`timokoesters/conduit@ebb38cd`](https://github.com/timokoesters/conduit/commit/ebb38cd) (2021-01-16)

## What changed vs step 69

| Rust change | C++ translation |
|---|---|
| **Respect logout_devices param** | **Translated** — Logout devices on password change |

## Implementation details

1. **Logout devices on password change** — Respect the `logout_devices` parameter when changing password

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
