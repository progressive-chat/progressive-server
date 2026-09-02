# Step 69 — "Fixing the incoming events algorithm (review with time)" (Conduit `b1ae2bb`)

Source: [`timokoesters/conduit@b1ae2bb`](https://github.com/timokoesters/conduit/commit/b1ae2bb) (2021-01-16)

## What changed vs step 68

| Rust change | C++ translation |
|---|---|
| **Fix incoming events algorithm** | **Translated** — Fixed incoming event handling |
| **Improved event review** | **Translated** — Better event review logic |

## Implementation details

1. **Incoming events algorithm** — Fixed incoming event handling
2. **Event review** — Better event review logic

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
