# Step 172 — "fix: improve locks" (Conduit `0eeba86`)

Source: [`timokoesters/conduit@0eeba86`](https://github.com/timokoesters/conduit/commit/0eeba86) (2021-08-03)

## What changed vs step 171

| Rust change | C++ translation |
|---|---|
| **Improve locks** | **Translated** — Improved locks |
| **Major client_server refactor** | **Translated** — Cleaner client_server |

## Implementation details

1. **Improved locks** — Fix and improve locks across the codebase
2. **Major client_server refactor** — Major refactor of client_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
