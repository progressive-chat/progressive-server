# Step 218 — "Use simple BTreeMap to store uiaa requests" (Conduit `3d25d46`)

Source: [`timokoesters/conduit@3d25d46`](https://github.com/timokoesters/conduit/commit/3d25d46) (2021-12-18)

## What changed vs step 217

| Rust change | C++ translation |
|---|---|
| **BTreeMap for UIAA** | **Translated** — BTreeMap for UIAA |

## Implementation details

1. **BTreeMap for UIAA** — Use simple BTreeMap to store uiaa requests (some uiaa requests contain plaintext passwords which should never be persisted to disk)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
