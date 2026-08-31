# Step 224 — "improvement: make state res actually work" (Conduit `6da4022`)

Source: [`timokoesters/conduit@6da4022`](https://github.com/timokoesters/conduit/commit/6da4022) (2021-03)

## What changed vs step 223

| Rust change | C++ translation |
|---|---|
| Improvement: make state res actually work. Major state resolution fixes and improvements. 13 files changed. | **Translated** — Our step 83 (`d71d94a_msc4297_state_res_v2`) is the working state-res. This commit fixes the Rust version. |

## Implementation details

- Our step 83 (`d71d94a_msc4297_state_res_v2`) is the working state-res. This commit fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
