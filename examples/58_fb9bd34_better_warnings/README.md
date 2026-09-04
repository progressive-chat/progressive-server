# Step 58 — "improvement: better warnings when server is unreachable" (Conduit `fb9bd34`)

Source: [`timokoesters/conduit@fb9bd34`](https://github.com/timokoesters/conduit/commit/fb9bd34) (2020-12-23)

## What changed vs step 57

| Rust change | C++ translation |
|---|---|
| **Better warnings when server is unreachable** | **Translated** — Error message now includes the actual error string from httplib |

## Implementation details

1. **Updated error message in `server_server.cpp`** — The federation request failure message now includes the actual error string from httplib (e.g., "Connection refused", "Host not found", "Timeout") instead of just the numeric error code.

**Status:** Real implementation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```