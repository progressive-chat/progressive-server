# Step 153 — "improvement: /search works for multiple rooms" (Conduit `dcac136`)

Source: [`timokoesters/conduit@dcac136`](https://github.com/timokoesters/conduit/commit/dcac136) (2021-06-21)

## What changed vs step 152

| Rust change | C++ translation |
|---|---|
| **/search works for multiple rooms** | **Translated** — Multi-room search |

## Implementation details

1. **Multi-room search** — /search works for multiple rooms

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
