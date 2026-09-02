# Step 115 — "feat: /devices route" (Conduit `71ed1b2`)

Source: [`timokoesters/conduit@71ed1b2`](https://github.com/timokoesters/conduit/commit/71ed1b2) (2021-04-21)

## What changed vs step 114

| Rust change | C++ translation |
|---|---|
| **/devices route** | **Translated** — /devices endpoint |

## Implementation details

1. **/devices endpoint** — Add /devices route for listing user devices

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
