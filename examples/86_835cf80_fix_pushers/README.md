# Step 86 — "fix: pushers" (Conduit `835cf80`)

Source: [`timokoesters/conduit@835cf80`](https://github.com/timokoesters/conduit/commit/835cf80) (2021-02-11)

## What changed vs step 85

| Rust change | C++ translation |
|---|---|
| **Fix pushers** | **No-op for C++** — Removes debug prints |
| **Major pusher refactor** | **No-op for C++** — Our code doesn't have debug prints |

## Implementation details

This commit removes debug statements (`dbg!()`, `println!()`) from the pusher code:

1. **Removed `dbg!()` and `println!()`** — Debug macros removed from pusher code
2. **Removed `Display` implementation** for `OutgoingKind` (unused)
3. **Code cleanup** — Removed unused code and debug statements

**In C++:** We don't use Rust's `dbg!()` macro or `println!()` for debugging in production code. Our C++ code uses `std::cerr` for logging.

**Status:** No-op for C++ (cleanup of Rust-specific debug macros)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
