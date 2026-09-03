# Step 248 — "fix: Use default port for healthcheck as fallback" (Conduit `44f7a85`)

Source: [`timokoesters/conduit@44f7a85`](https://github.com/timokoesters/conduit/commit/44f7a85) (2022-01-28)

## What changed vs step 247

| Rust change | C++ translation |
|---|---|
| **Healthcheck default port fallback** | **Translated** — Healthcheck default port |

## Implementation details

1. **Healthcheck default port** — Use default port for healthcheck as fallback (Conduit can start without a specific port being configured)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
