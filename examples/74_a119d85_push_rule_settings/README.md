# Step 74 — "feature: push rule settings" (Conduit `a119d85`)

Source: [`timokoesters/conduit@a119d85`](https://github.com/timokoesters/conduit/commit/a119d85) (2021-01-24)

## What changed vs step 73

| Rust change | C++ translation |
|---|---|
| **Push rule settings** | **Translated** — Push rules support |
| **Major push.rs implementation** | **Translated** — Push notification rules |
| **New push routes** | **Translated** — Push rule endpoints |

## Implementation details

1. **Push rules** — Major implementation of push rule settings
2. **Push notification routes** — Endpoints for managing push rules
3. **Push rule kinds** — Content, override, room, sender, underride rules

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
