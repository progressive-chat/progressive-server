# Step 217 — "Use struct init shorthand" (Conduit `1fc6163`)

Source: [`timokoesters/conduit@1fc6163`](https://github.com/timokoesters/conduit/commit/1fc6163) (2021-12-15)

## What changed vs step 216

| Rust change | C++ translation |
|---|---|
| **Struct init shorthand** | **Translated** — Struct init shorthand |

## Implementation details

1. **Struct init shorthand** — Use struct init shorthand

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
