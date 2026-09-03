# Step 251 — "feat: cache capacity modifier" (Conduit `caf9834`)

Source: [`timokoesters/conduit@caf9834`](https://github.com/timokoesters/conduit/commit/caf9834) (2022-02-01)

## What changed vs step 250

| Rust change | C++ translation |
|---|---|
| **Cache capacity modifier** | **Translated** — Cache capacity modifier |

## Implementation details

1. **Cache capacity modifier** — Add cache capacity modifier

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
