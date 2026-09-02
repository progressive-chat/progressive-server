# Step 231 — "feat: config option for rocksdb max open files" (Conduit `d434dfb`)

Source: [`timokoesters/conduit@d434dfb`](https://github.com/timokoesters/conduit/commit/d434dfb) (2022-01-14)

## What changed vs step 230

| Rust change | C++ translation |
|---|---|
| **Rocksdb max open files config** | **Translated** — Rocksdb max open files |

## Implementation details

1. **Rocksdb max open files** — Add config option for rocksdb max open files

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
