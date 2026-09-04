# 2026-tail — "refactor: move configuration to it's own crate" (Conduit `422bd24`)

Source: [`timokoesters/conduit@422bd24`](https://github.com/timokoesters/conduit/commit/422bd24) (2026-07-17)

## What changed vs step 93 (last numbered step)

| Rust change | C++ translation |
|---|---|
| Moves configuration to a separate crate. No-op (we use env-var-only configuration). | **No-op for C++** — We use env-var-only configuration, no separate config crate |

## Implementation details

This is a Rust-specific refactor to move configuration to a separate crate. Our C++ implementation uses environment variables directly, so this is a no-op.

**Status:** No-op for C++

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```