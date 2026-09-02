# Step 202 — "improvement: make pdu cache capacity configurable" (Conduit `73d8766`)

Source: [`timokoesters/conduit@73d8766`](https://github.com/timokoesters/conduit/commit/73d8766) (2021-09-01)

## What changed vs step 201

| Rust change | C++ translation |
|---|---|
| **PDU cache capacity configurable** | **Translated** — PDU cache capacity config |

## Implementation details

1. **PDU cache capacity config** — Make pdu cache capacity configurable

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
