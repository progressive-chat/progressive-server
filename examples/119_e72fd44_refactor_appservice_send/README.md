# Step 119 — "Refactor send_request for appservices" (Conduit `e72fd44`)

Source: [`timokoesters/conduit@e72fd44`](https://github.com/timokoesters/conduit/commit/e72fd44) (2021-04-23)

## What changed vs step 118

| Rust change | C++ translation |
|---|---|
| **Refactor send_request for appservices** | **Translated** — Appservice send refactor |

## Implementation details

1. **Appservice send refactor** — Refactor send_request for appservices

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
