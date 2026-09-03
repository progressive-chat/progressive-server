# Step 249 — "Refactor admin code to always defer command processing" (Conduit `677f044`)

Source: [`timokoesters/conduit@677f044`](https://github.com/timokoesters/conduit/commit/677f044) (2022-01-31)

## What changed vs step 248

| Rust change | C++ translation |
|---|---|
| **Defer admin commands** | **Translated** — Defer admin commands |
| **Major admin refactor** | **Translated** — Cleaner admin code |

## Implementation details

1. **Defer admin commands** — Refactor admin code to always defer command processing
2. **Major admin refactor** — Major refactor of admin code

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
