# 2026-tail — "fix: don't perform identity assertion on appservice-only endpoints" (Conduit `98e2bed`)

Source: [`timokoesters/conduit@98e2bed`](https://github.com/timokoesters/conduit/commit/98e2bed) (2026-01-22)

## What changed vs step 91 (last numbered step)

| Rust change | C++ translation |
|---|---|
| Appservice ping endpoint only accepts `AuthScheme::AppserviceToken` (matched via `appservice_id_from_token`). | **Translated** — Implemented in POST /_matrix/client/v1/appservice/{appserviceId}/ping |

## Implementation details

The `/appservice/{appserviceId}/ping` endpoint in main.cpp:
1. Extracts token via `extract_token(req)` 
2. Validates token is an appservice token via `appservice_id_from_token`
3. Returns 403 if not an appservice token
4. Validates appservice ID matches request body
5. Returns appropriate errors for mismatches

**Status:** Real implementation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```