# Step 189 — "improvement: better prev event fetching, perf improvements" (Conduit `bf7e019`)

Source: [`timokoesters/conduit@bf7e019`](https://github.com/timokoesters/conduit/commit/bf7e019) (2021-08-17)

## What changed vs step 188

| Rust change | C++ translation |
|---|---|
| **Better prev event fetching** | **Translated** — Better prev event fetch |
| **Major rooms refactor** | **Translated** — Cleaner rooms code |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Better prev event fetch** — Better prev event fetching
2. **Major rooms refactor** — Major refactor of rooms.rs
3. **Major server_server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
