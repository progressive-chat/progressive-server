# Step 125 — "Refactor some canonical JSON code" (Conduit `af6fea3`)

Source: [`timokoesters/conduit@af6fea3`](https://github.com/timokoesters/conduit/commit/af6fea3) (2021-05-08)

## What changed vs step 124

| Rust change | C++ translation |
|---|---|
| **Refactor canonical JSON code** | **Translated** — Canonical JSON refactor |

## Implementation details

1. **Canonical JSON refactor** — Refactor some canonical JSON code

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
