# Step 495 — "Return an error when signing an event fails Prevents the server from crashing/become unresponsive when overly long messages are sent" (Conduit `07a3a6f`)

Source: [`timokoesters/conduit@07a3a6f`](https://github.com/timokoesters/conduit/commit/07a3a6f) (2022-04)

## What changed vs step 494

| Rust change | C++ translation |
|---|---|
| Return an error when signing an event fails. Prevents server from crashing/becoming unresponsive when overly long messages are sent. | **Translated** — Our event signing (step 8) returns errors. This prevents crashes on signing failures. |

## Implementation details

- Our event signing (step 8) returns errors. This prevents crashes on signing failures.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
