# Step 274 — "Return only event content in account_data endpoints, not the entire event" (Conduit `e1c4e5c`)

Source: [`timokoesters/conduit@e1c4e5c`](https://github.com/timokoesters/conduit/commit/e1c4e5c) (2021-04)

## What changed vs step 273

| Rust change | C++ translation |
|---|---|
| Return only event content in account_data endpoints, not the entire event. Fixes API to match spec. | **Translated** — Our account_data (step 30, 234) returns content. This fixes the Rust version. |

## Implementation details

- Our account_data (step 30, 234) returns content. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
