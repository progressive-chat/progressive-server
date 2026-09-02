# Step 73 — "WIP gather and update forward extremities" (Conduit `c65bde4`)

Source: [`timokoesters/conduit@c65bde4`](https://github.com/timokoesters/conduit/commit/c65bde4) (2021-01-18)

## What changed vs step 72

| Rust change | C++ translation |
|---|---|
| **Gather and update forward extremities** | **Translated** — Forward extremity tracking |
| **WIP: state resolution improvements** | **Translated** — State res WIP |

## Implementation details

1. **Forward extremities** — Gather and update forward extremities in database
2. **State resolution** — WIP improvements to state resolution

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
