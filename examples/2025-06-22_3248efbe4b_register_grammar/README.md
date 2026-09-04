# 2024/2025-tail — "fix(registration): enforce the strict user ID grammar" (Conduit `3248efbe4b`)

Source: [`timokoesters/conduit@3248efbe4b`](https://github.com/timokoesters/conduit/commit/3248efbe4b) (2025-06-22)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| `register_route` rejects localparts that don't match the strict grammar; returns M_INVALID_USERNAME. | **Translated** — Our `localpart_valid` uses strict validation. |

## Implementation details

This commit changes user ID validation from `!is_historical()` to `validate_strict()`:

1. **get_register_available_route**: Uses `validate_strict()` instead of `!is_historical()`
2. **register_route**: Same change for registration validation

**Our implementation**: Our `localpart_valid` in handlers.cpp already enforces strict grammar (alphanumeric, underscore, hyphen, dot).

**Status:** Already implemented (no changes needed).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```