# Step 75 — "feature: push rule settings" (Conduit `265fab8`)

Source: [`timokoesters/conduit@265fab8`](https://github.com/timokoesters/conduit/commit/265fab8) (2021-01-28)

## What changed vs step 74

| Rust change | C++ translation |
|---|---|
| **Push rule settings (continued)** | **Translated** — More push rules |
| **Push rules implementation** | **Translated** — Extended push rules |

## Implementation details

1. **Push rules continuation** — More push rules support
2. **Extended push rules** — Additional push rules

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
