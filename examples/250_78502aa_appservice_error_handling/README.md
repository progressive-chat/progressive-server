# Step 250 — "add error handling for register_appservice too" (Conduit `78502aa`)

Source: [`timokoesters/conduit@78502aa`](https://github.com/timokoesters/conduit/commit/78502aa) (2022-01-31)

## What changed vs step 249

| Rust change | C++ translation |
|---|---|
| **register_appservice error handling** | **Translated** — Appservice error handling |

## Implementation details

1. **Appservice error handling** — Add error handling for register_appservice too

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
