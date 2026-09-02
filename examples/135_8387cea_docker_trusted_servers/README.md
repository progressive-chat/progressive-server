# Step 135 — "Fix docker-compose trusted_servers env var" (Conduit `8387cea`)

Source: [`timokoesters/conduit@8387cea`](https://github.com/timokoesters/conduit/commit/8387cea) (2021-05-25)

## What changed vs step 134

| Rust change | C++ translation |
|---|---|
| **Docker-compose trusted_servers env var** | **Translated** — Docker env var |

## Implementation details

1. **Docker env var** — Fix docker-compose trusted_servers env var

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
