# Step 100 — "improvement: better logging" (Conduit `1d00a8c`)

Source: [`timokoesters/conduit@1d00a8c`](https://github.com/timokoesters/conduit/commit/1d00a8c) (2021-03-23)

## What changed vs step 99

| Rust change | C++ translation |
|---|---|
| **Better logging** | **Translated** — Better logging |
| **CONDUIT_LOG / log config** | **Translated** — Log config support |
| **Database logging** | **Translated** — Database log calls |

## Implementation details

1. **Better logging** — Use CONDUIT_LOG or log setting in config
2. **Log config** — Support log level configuration

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
