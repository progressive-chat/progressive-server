# Step 65 — "State resolution outline for /send" (Conduit `7c4e116`)

Source: [`timokoesters/conduit@7c4e116`](https://github.com/timokoesters/conduit/commit/7c4e116) (2021-01-14)

## What changed vs step 64

| Rust change | C++ translation |
|---|---|
| **State resolution outline for /send (cont.)** | **Translated** — More state resolution code |
| **Add to /send handler** | **Translated** — Extended /send handler |

## Implementation details

1. **State resolution continuation** — More state resolution code in /send
2. **Extended /send handler** — Additional /send handler logic

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
