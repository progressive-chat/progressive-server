# Step 297 — "fix: state resolution bugs" (Conduit `daa1fc9`)

Source: [`timokoesters/conduit@daa1fc9`](https://github.com/timokoesters/conduit/commit/daa1fc9) (2021-05)

## What changed vs step 296

| Rust change | C++ translation |
|---|---|
| Fix: state resolution bugs. Multiple state resolution fixes. 3 files changed. | **Translated** — Our state-res (step 83 `d71d94a_msc4297_state_res_v2`) is the fixed version. This fixes the Rust version. |

## Implementation details

- Our state-res (step 83 `d71d94a_msc4297_state_res_v2`) is the fixed version. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
