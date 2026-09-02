# Step 211 — "Initial implementation of /report, fixing #13" (Conduit `ccf501a`)

Source: [`timokoesters/conduit@ccf501a`](https://github.com/timokoesters/conduit/commit/ccf501a) (2021-10-18)

## What changed vs step 210

| Rust change | C++ translation |
|---|---|
| **/report endpoint** | **Translated** — /report |

## Implementation details

1. **/report** — Initial implementation of /report (fixes #13)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
