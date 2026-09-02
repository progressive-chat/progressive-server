# Step 235 — "Add some debug/info if user was found" (Conduit `52284ef`)

Source: [`timokoesters/conduit@52284ef`](https://github.com/timokoesters/conduit/commit/52284ef) (2022-01-16)

## What changed vs step 234

| Rust change | C++ translation |
|---|---|
| **Debug/info if user found** | **Translated** — User found debug |

## Implementation details

1. **User found debug** — Add some debug/info if user was found

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
