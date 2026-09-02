# Step 158 — "Change default port in docker to the new conduit default port 6167" (Conduit `6a96cfa`)

Source: [`timokoesters/conduit@6a96cfa`](https://github.com/timokoesters/conduit/commit/6a96cfa) (2021-07-06)

## What changed vs step 157

| Rust change | C++ translation |
|---|---|
| **Docker default port 6167** | **Translated** — Docker port change |

## Implementation details

1. **Docker port change** — Change default port in docker to 6167 and fix docker healthcheck

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
