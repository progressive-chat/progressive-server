# Step 425 — "Return the ID of the appservice that was created by register_appservice" (Conduit `28d3b34`)

Source: [`timokoesters/conduit@28d3b34`](https://github.com/timokoesters/conduit/commit/28d3b34) (2022-01)

## What changed vs step 424

| Rust change | C++ translation |
|---|---|
| Return the ID of the appservice that was created by register_appservice. API response improvement. 2 files changed. | **Translated** — Our appservice registration returns the ID. This ensures the Rust version does too. |

## Implementation details

- Our appservice registration returns the ID. This ensures the Rust version does too.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
