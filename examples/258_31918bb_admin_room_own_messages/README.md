# Step 258 — "Fix admin room processing commands from its own messages" (Conduit `31918bb`)

Source: [`timokoesters/conduit@31918bb`](https://github.com/timokoesters/conduit/commit/31918bb) (2022-02-05)

## What changed vs step 257

| Rust change | C++ translation |
|---|---|
| **Admin room own messages** | **Translated** — Admin room own messages |

## Implementation details

1. **Admin room own messages** — Fix admin room processing commands from its own messages

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
