# Step 108 — "fix: don't do expensive operation on local /send" (Conduit `001d8dc`)

Source: [`timokoesters/conduit@001d8dc`](https://github.com/timokoesters/conduit/commit/001d8dc) (2021-04-14)

## What changed vs step 107

| Rust change | C++ translation |
|---|---|
| **Don't do expensive operation on local /send** | **Translated** — Skip expensive ops on local send |

## Implementation details

1. **Local /send optimization** — Don't do expensive operation on local /send

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
