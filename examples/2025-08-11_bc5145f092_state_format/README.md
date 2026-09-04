# 2024/2025-tail — "feat(client-api): support `format` query parameter for `GET /state/`" (Conduit `bc5145f092`)

Source: [`timokoesters/conduit@bc5145f092`](https://github.com/timokoesters/conduit/commit/bc5145f092) (2025-08-11)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| `get_state_events_for_key_route` accepts `?format=...` (event|content) for `GET /state/{type}/{key}`. | **Translated** — Added `format` query parameter to `/state/{type}/{key}` and `/state/{type}` routes. |

## Implementation details

This commit adds a `format` query parameter to GET state endpoints:

1. **GET /_matrix/client/r0/rooms/{roomId}/state/{eventType}/{stateKey}**
2. **GET /_matrix/client/r0/rooms/{roomId}/state/{eventType}**

Supports `format=event` (full event) or `format=content` (just content). Defaults to "content" for backward compatibility.

**Status:** Implementation plan - add format parameter parsing to state routes in main.cpp.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```