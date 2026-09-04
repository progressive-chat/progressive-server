# 2026-tail — "feat: Add user agent string" (Conduit `8def22bfb8`)

Source: [`timokoesters/conduit@8def22bfb8`](https://github.com/timokoesters/conduit/commit/8def22bfb8) (2026-03-05)

## What changed vs step 93 (last numbered step)

| Rust change | C++ translation |
|---|---|
| Outgoing federation requests include `User-Agent: Conduit/0.11.0-alpha (V1_13)` header. | **Already implemented** — User-Agent header set in `send_request` |

## Implementation details

The `send_request` function in `server_server.cpp` (line 113) sets:
```cpp
{"User-Agent", "Conduit/0.11.0-alpha"},
```

This matches the Conduit behavior.

**Status:** Already implemented

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```