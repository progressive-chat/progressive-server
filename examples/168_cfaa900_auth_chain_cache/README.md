# Step 168 — "improvement: auth chain cache" (Conduit `cfaa900`)

Source: [`timokoesters/conduit@cfaa900`](https://github.com/timokoesters/conduit/commit/cfaa900) (2021-07-20)

## What changed vs step 167

| Rust change | C++ translation |
|---|---|
| **Auth chain cache** | **Translated** — Auth chain cache |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Auth chain cache** — Add auth chain cache
2. **Major server_server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
