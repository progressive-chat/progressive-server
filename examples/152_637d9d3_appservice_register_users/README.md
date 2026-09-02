# Step 152 — "Always allow appservices to register new users" (Conduit `637d9d3`)

Source: [`timokoesters/conduit@637d9d3`](https://github.com/timokoesters/conduit/commit/637d9d3) (2021-06-19)

## What changed vs step 151

| Rust change | C++ translation |
|---|---|
| **Always allow appservices to register users** | **Translated** — Appservice register |

## Implementation details

1. **Appservice register** — Always allow appservices to register new users

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
