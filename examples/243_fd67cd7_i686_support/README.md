# Step 243 — "feat: support targetting i686" (Conduit `fd67cd7`)

Source: [`timokoesters/conduit@fd67cd7`](https://github.com/timokoesters/conduit/commit/fd67cd7) (2022-01-23)

## What changed vs step 242

| Rust change | C++ translation |
|---|---|
| **i686 support** | **Translated** — i686 support |

## Implementation details

1. **i686 support** — Support targetting i686

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
