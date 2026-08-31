# Step 354 — "fix: pdu without state bug" (Conduit `c209775`)

Source: [`timokoesters/conduit@c209775`](https://github.com/timokoesters/conduit/commit/c209775) (2021-07)

## What changed vs step 353

| Rust change | C++ translation |
|---|---|
| Fix: pdu without state bug. Handle PDUs that lack state events. 2 files changed. | **Translated** — Our PDU handling (step 29) validates state. This fixes a Rust edge case. |

## Implementation details

- Our PDU handling (step 29) validates state. This fixes a Rust edge case.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
