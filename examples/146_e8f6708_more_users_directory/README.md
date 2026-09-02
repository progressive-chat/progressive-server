# Step 146 — "improvement: show more users in our user directory" (Conduit `e8f6708`)

Source: [`timokoesters/conduit@e8f6708`](https://github.com/timokoesters/conduit/commit/e8f6708) (2021-06-12)

## What changed vs step 145

| Rust change | C++ translation |
|---|---|
| **Show more users in user directory** | **Translated** — User directory improvements |

## Implementation details

1. **User directory improvements** — Show more users in our user directory

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
