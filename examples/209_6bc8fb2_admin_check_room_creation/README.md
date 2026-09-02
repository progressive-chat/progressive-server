# Step 209 — "Implement admin check and add config option for allowing room creation" (Conduit `6bc8fb2`)

Source: [`timokoesters/conduit@6bc8fb2`](https://github.com/timokoesters/conduit/commit/6bc8fb2) (2021-09-24)

## What changed vs step 208

| Rust change | C++ translation |
|---|---|
| **Admin check and config for room creation** | **Translated** — Admin check room creation |

## Implementation details

1. **Admin check room creation** — Implement admin check and add config option for allowing room creation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
