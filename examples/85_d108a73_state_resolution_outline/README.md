# Step 85 — "State resolution outline for /send" (Conduit `d108a73`)

Source: [`timokoesters/conduit@d108a73`](https://github.com/timokoesters/conduit/commit/d108a73) (2021-02-09)

## What changed vs step 84

| Rust change | C++ translation |
|---|---|
| **State resolution outline for /send** | **Translated** — More state resolution code |

## Implementation details

1. **State resolution outline** — More state resolution code in /send

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
