# Step 102 — "improvement: /event route" (Conduit `f3f95a7`)

Source: [`timokoesters/conduit@f3f95a7`](https://github.com/timokoesters/conduit/commit/f3f95a7) (2021-04-07)

## What changed vs step 101

| Rust change | C++ translation |
|---|---|
| **/event route** | **Translated** — /event route |

## Implementation details

1. **/event route** — Add /event route for fetching single events

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
