# Step 200 — "registration default true" (Conduit `9ec8b7f`)

Source: [`timokoesters/conduit@9ec8b7f`](https://github.com/timokoesters/conduit/commit/9ec8b7f) (2021-08-31)

## What changed vs step 199

| Rust change | C++ translation |
|---|---|
| **Registration default true** | **Translated** — Registration default true |

## Implementation details

1. **Registration default true** — Set registration default to true

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
