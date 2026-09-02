# Step 169 — "fix: pdu without state bug" (Conduit `c209775`)

Source: [`timokoesters/conduit@c209775`](https://github.com/timokoesters/conduit/commit/c209775) (2021-07-29)

## What changed vs step 168

| Rust change | C++ translation |
|---|---|
| **PDU without state bug** | **Translated** — PDU state bug fix |

## Implementation details

1. **PDU state bug fix** — Fix pdu without state bug

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
