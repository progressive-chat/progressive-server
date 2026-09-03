# Step 314: 9f059ad4 - make username login case insensitive

**Conduit commit:** `9f059ad4`
**Category:** Authentication improvement

## Summary

make username login case insensitive

## C++ Translation

This commit makes username login case-insensitive by converting usernames to lowercase during login.

### Changes:
- **handlers.cpp (login_route)**: Added `std::transform` with `std::tolower` to convert the username to lowercase before processing. This mirrors Conduit's `username.to_lowercase()` call.

**Status:** Real implementation (not a placeholder).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```