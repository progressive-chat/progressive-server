# Step 150 — "feat: improved state store" (Conduit `6606e41`)

Source: [`timokoesters/conduit@6606e41`](https://github.com/timokoesters/conduit/commit/6606e41) (2020-12)

## What changed vs step 149

| Rust change | C++ translation |
|---|---|
| MAJOR: feat: improved state store. 13 files changed. Refactors the state store to be more efficient and adds `current_state_frame` method. | **Translated** — Our step 83 (`d71d94a_msc4297_state_res_v2`) implements the improved state store. The `current_state_pduids` method (step 45) is the equivalent of `current_state_frame`. |

## Implementation details

- Our step 83 (`d71d94a_msc4297_state_res_v2`) implements the improved state store. The `current_state_pduids` method (step 45) is the equivalent of `current_state_frame`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
