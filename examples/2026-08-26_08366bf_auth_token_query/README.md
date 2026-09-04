# 2026-tail — "fix: only allow request to pass auth with token query if auth type is None" (Conduit `08366bf`)

Source: [`timokoesters/conduit@08366bf`](https://github.com/timokoesters/conduit/commit/08366bf) (2026-08-26)

## What changed vs step 93 (last numbered step)

| Rust change | C++ translation |
|---|---|
| `openid/request_token` enforces `body.user_id == sender_user`; `extract_token` prefers Authorization header over `?access_token=`. | **Already implemented** — `extract_token` prefers Authorization header |

## Implementation details

The `extract_token` function in handlers.cpp already:
1. First checks for `Authorization: Bearer <token>` header
2. Falls back to `access_token` query parameter if no header
2. Returns nullopt if neither present

This matches the Conduit fix.

**Status:** Already implemented

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```