# Step 36 — "fix: don't panic on bad server names" (Conduit `0b26320`)

Source: [`timokoesters/conduit@0b26320`](https://github.com/timokoesters/conduit/commit/0b26320) (2020-09-15)

## What changed vs step 35

| Rust change | C++ translation |
|---|---|
| **`try_into_http_request().unwrap()` → `.map_err(...).map_err(...)`** | **Translated** — Added proper error handling for HTTP request conversion |
| **`serde_json::from_slice().unwrap()` → `.expect(...)`** | **Translated** — Added proper error handling for JSON parsing |
| **`.unwrap()` on sign_json → `.expect(...)`** | **Translated** — Added proper error handling for signing |
| **`T::IncomingResponse::try_from(...).unwrap()`** | **Translated** — Added proper error handling with `.expect()` |
| **Added `warn!` logging for errors** | **Translated** — Added warning logging |

## Implementation details

This commit fixes several `.unwrap()` calls that could panic on bad server names or invalid responses:

1. **`try_into_http_request()`** - Now returns proper error instead of panicking
2. **JSON parsing** - Uses `.expect()` with descriptive message
3. **Signing** - Uses `.expect()` with descriptive message
4. **Response parsing** - Uses `.expect()` with proper error handling

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
