# Step 120 — "Refactor usage of CanonicalJsonValue" (Conduit `2e1d7d1`)

Source: [`timokoesters/conduit@2e1d7d1`](https://github.com/timokoesters/conduit/commit/2e1d7d1) (2021-04-26)

## What changed vs step 119

| Rust change | C++ translation |
|---|---|
| **Refactor CanonicalJsonValue usage** | **Translated** — CanonicalJson refactor |

## Implementation details

1. **CanonicalJson refactor** — Refactor usage of CanonicalJsonValue

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
