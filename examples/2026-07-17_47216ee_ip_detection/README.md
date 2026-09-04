# 2026-tail — "feat: make IP address detection method configurable" (Conduit `47216ee`)

Source: [`timokoesters/conduit@47216ee`](https://github.com/timokoesters/conduit/commit/47216ee) (2026-07-17)

## What changed vs step 93 (last numbered step)

| Rust change | C++ translation |
|---|---|
| Adds `WELL_KNOWN_CLIENT`/`WELL_KNOWN_SERVER` env vars to override defaults; respects `X-Forwarded-For` for client IP. | **Partial** — WELL_KNOWN env vars implemented; X-Forwarded-For not yet handled |

## Implementation details

- **WELL_KNOWN_CLIENT/SERVER env vars** — Implemented in main.cpp (lines 674-675)
- **X-Forwarded-For support** — Not yet implemented in rate limiting bucket key

**Status:** Partial implementation — WELL_KNOWN env vars done, X-Forwarded-For pending

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```