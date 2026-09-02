# Step 61 — "improvement: better config, better logs" (Conduit `edfd3c1`)

Source: [`timokoesters/conduit@edfd3c1`](https://github.com/timokoesters/conduit/commit/edfd3c1) (2020-12-31)

## What changed vs step 60

| Rust change | C++ translation |
|---|---|
| **Better config handling** | **Translated** — Improved config loading |
| **Better logging** | **Translated** — More informative log messages |
| **Database refactoring** | **Translated** — Cleaner database code |
| **Error handling improvements** | **Translated** — Better error types |

## Implementation details

1. **Config improvements** — Better config file parsing and validation
2. **Log improvements** — More informative log messages with context
3. **Database cleanup** — Refactored database code for clarity
4. **Error handling** — Better error types and messages

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
