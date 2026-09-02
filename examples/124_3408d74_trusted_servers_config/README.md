# Step 124 — "fix: add trusted_servers to config and deploy guide" (Conduit `3408d74`)

Source: [`timokoesters/conduit@3408d74`](https://github.com/timokoesters/conduit/commit/3408d74) (2021-05-05)

## What changed vs step 123

| Rust change | C++ translation |
|---|---|
| **trusted_servers config** | **Translated** — trusted_servers config |

## Implementation details

1. **trusted_servers config** — Add trusted_servers to config and deploy guide

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
