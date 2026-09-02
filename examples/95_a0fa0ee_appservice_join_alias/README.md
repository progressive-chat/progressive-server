# Step 95 — "fix: join appservice room with alias" (Conduit `a0fa0ee`)

Source: [`timokoesters/conduit@a0fa0ee`](https://github.com/timokoesters/conduit/commit/a0fa0ee) (2021-03-18)

## What changed vs step 94

| Rust change | C++ translation |
|---|---|
| **Join appservice room with alias** | **Translated** — Appservice room join fix |

## Implementation details

1. **Appservice room join** — Fix joining appservice room with alias

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
