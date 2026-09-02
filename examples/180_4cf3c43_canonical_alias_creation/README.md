# Step 180 — "Try to set canonical room alias on room creation." (Conduit `4cf3c43`)

Source: [`timokoesters/conduit@4cf3c43`](https://github.com/timokoesters/conduit/commit/4cf3c43) (2021-08-12)

## What changed vs step 179

| Rust change | C++ translation |
|---|---|
| **Canonical room alias on creation** | **Translated** — Set canonical alias on room creation |

## Implementation details

1. **Canonical alias on creation** — Try to set canonical room alias on room creation (closes #123)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
