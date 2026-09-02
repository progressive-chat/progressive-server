# Step 147 — "feat: /state" (Conduit `3c9ea55`)

Source: [`timokoesters/conduit@3c9ea55`](https://github.com/timokoesters/conduit/commit/3c9ea55) (2021-06-14)

## What changed vs step 146

| Rust change | C++ translation |
|---|---|
| **/state** | **Translated** — /state endpoint |

## Implementation details

1. **/state endpoint** — Add /state federation endpoint

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
