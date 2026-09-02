# Step 60 — "fix: rare state races" (Conduit `df16b2b`)

Source: [`timokoesters/conduit@df16b2b`](https://github.com/timokoesters/conduit/commit/df16b2b) (2020-12-31)

## What changed vs step 59

| Rust change | C++ translation |
|---|---|
| **Fix rare state races** | **Translated** — Better state race handling |
| **State event handling improvements** | **Translated** — Race-free state updates |

## Implementation details

1. **State race fixes** — Prevent rare state races during concurrent updates
2. **Better state event handling** — Improved state event processing

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
