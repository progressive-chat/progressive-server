# Step 62 — "fix: send presence updates when going offline" (Conduit `d45d033`)

Source: [`timokoesters/conduit@d45d033`](https://github.com/timokoesters/conduit/commit/d45d033) (2021-01-10)

## What changed vs step 61

| Rust change | C++ translation |
|---|---|
| **Send presence updates when going offline** | **Translated** — Presence update on offline |
| **EDU handling improvements** | **Translated** — Better EDU processing |

## Implementation details

1. **Presence updates on offline** — Send presence update when user goes offline
2. **EDU handling** — Better EDU processing for presence

## Note
Remaining bug noted: conduit sends presence updates every 5 minutes even if user is already offline (not fixed in this commit).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
