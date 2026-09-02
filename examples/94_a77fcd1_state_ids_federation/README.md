# Step 94 — "feat: implement /state_ids and fix federation stuff" (Conduit `a77fcd1`)

Source: [`timokoesters/conduit@a77fcd1`](https://github.com/timokoesters/conduit/commit/a77fcd1) (2021-03-18)

## What changed vs step 93

| Rust change | C++ translation |
|---|---|
| **Implement /state_ids** | **Translated** — /state_ids endpoint |
| **Fix federation stuff** | **Translated** — Federation fixes |

## Implementation details

1. **/state_ids endpoint** — Implement /state_ids federation endpoint
2. **Federation fixes** — Various federation fixes

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
